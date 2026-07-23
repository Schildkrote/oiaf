//go:build windows

// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"syscall"
	"unsafe"
)

var (
	wevtapi      = syscall.NewLazyDLL("wevtapi.dll")
	evtSubscribe = wevtapi.NewProc("EvtSubscribe")
	evtNext      = wevtapi.NewProc("EvtNext")
	evtRender    = wevtapi.NewProc("EvtRender")
	evtClose     = wevtapi.NewProc("EvtClose")
)

const (
	evtSubscribeToRealtimeEvents = 1
	evtRenderEventXML            = 1
	securityAuditingProviderGUID = "{54849625-5478-4994-A5BA-3E3B0328C30D}"
)

type EventSource struct {
	cfg    *Config
	logger *slog.Logger
	handle uintptr
}

func NewEventSource(cfg *Config, logger *slog.Logger) (*EventSource, error) {
	return &EventSource{cfg: cfg, logger: logger}, nil
}

func (s *EventSource) Subscribe(ctx context.Context, out chan<- EventRecord) error {
	query := buildQuery(s.cfg.EventIDs)
	channelPtr, err := syscall.UTF16PtrFromString("Security")
	if err != nil {
		return fmt.Errorf("utf16 channel: %w", err)
	}
	queryPtr, err := syscall.UTF16PtrFromString(query)
	if err != nil {
		return fmt.Errorf("utf16 query: %w", err)
	}

	handle, _, callErr := evtSubscribe.Call(
		0,
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		0,
		0,
		0,
		0,
		evtSubscribeToRealtimeEvents,
	)
	if handle == 0 {
		return fmt.Errorf("EvtSubscribe failed: %v", callErr)
	}
	s.handle = handle

	s.logger.Info("subscribed to security event log", "query", query)

	eventHandles := make([]uintptr, 16)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		var returned uint32
		ret, _, _ := evtNext.Call(
			handle,
			uintptr(len(eventHandles)),
			uintptr(unsafe.Pointer(&eventHandles[0])),
			1000,
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 || returned == 0 {
			continue
		}

		for i := uint32(0); i < returned; i++ {
			xmlBytes, renderErr := renderEvent(eventHandles[i])
			evtClose.Call(eventHandles[i])
			if renderErr != nil {
				s.logger.Debug("render failed", "error", renderErr)
				continue
			}

			rec, parseErr := ParseEventXML(xmlBytes)
			if parseErr != nil {
				s.logger.Debug("parse failed", "error", parseErr)
				continue
			}

			select {
			case out <- rec:
			case <-ctx.Done():
				return nil
			}
		}
	}
}

func (s *EventSource) Close() {
	if s.handle != 0 {
		evtClose.Call(s.handle)
		s.handle = 0
	}
}

func renderEvent(eventHandle uintptr) ([]byte, error) {
	var bufUsed uint32
	evtRender.Call(0, eventHandle, evtRenderEventXML, 0, 0, uintptr(unsafe.Pointer(&bufUsed)), 0)
	if bufUsed == 0 {
		return nil, fmt.Errorf("empty event")
	}

	buf := make([]uint16, bufUsed/2+1)
	var propCount uint32
	ret, _, callErr := evtRender.Call(
		0,
		eventHandle,
		evtRenderEventXML,
		uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufUsed)),
		uintptr(unsafe.Pointer(&propCount)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("EvtRender: %v", callErr)
	}

	return []byte(syscall.UTF16ToString(buf)), nil
}

func buildQuery(eventIDs []int) string {
	if len(eventIDs) == 0 {
		return "*"
	}
	parts := make([]string, len(eventIDs))
	for i, id := range eventIDs {
		parts[i] = fmt.Sprintf("(EventID=%d)", id)
	}
	return fmt.Sprintf("*[System[%s]]", strings.Join(parts, " or "))
}
