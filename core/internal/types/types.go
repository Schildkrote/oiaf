// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type IdentityType string

const (
	IdentityTypePerson         IdentityType = "person"
	IdentityTypeServiceAccount IdentityType = "service_account"
	IdentityTypeMachine        IdentityType = "machine"
)

type Sensitivity string

const (
	SensitivityLow      Sensitivity = "low"
	SensitivityMedium   Sensitivity = "medium"
	SensitivityHigh     Sensitivity = "high"
	SensitivityCritical Sensitivity = "critical"
)

type Decision string

const (
	DecisionAllow     Decision = "allow"
	DecisionDeny      Decision = "deny"
	DecisionChallenge Decision = "challenge"
	DecisionAlert     Decision = "alert"
)

type ChallengeStatus string

const (
	ChallengeStatusPending  ChallengeStatus = "pending"
	ChallengeStatusApproved ChallengeStatus = "approved"
	ChallengeStatusDenied   ChallengeStatus = "denied"
	ChallengeStatusExpired  ChallengeStatus = "expired"
	ChallengeStatusFailed   ChallengeStatus = "failed"
)

type MFAMethod string

const (
	MFAMethodTOTP     MFAMethod = "totp"
	MFAMethodPush     MFAMethod = "push"
	MFAMethodWebAuthn MFAMethod = "webauthn"
	MFAMethodEmail    MFAMethod = "email"
	MFAMethodSMS      MFAMethod = "sms"
)

type FactorStatus string

const (
	FactorStatusPendingActivation FactorStatus = "pending_activation"
	FactorStatusActive            FactorStatus = "active"
	FactorStatusRevoked           FactorStatus = "revoked"
)

type Role string

const (
	RoleAdmin   Role = "admin"
	RoleAuditor Role = "auditor"
	RoleAdapter Role = "adapter"
	RoleService Role = "service"
)

type ActorType string

const (
	ActorUser    ActorType = "user"
	ActorAdapter ActorType = "adapter"
	ActorAdmin   ActorType = "admin"
	ActorSystem  ActorType = "system"
)

type TargetType string

const (
	TargetIdentity  TargetType = "identity"
	TargetResource  TargetType = "resource"
	TargetPolicy    TargetType = "policy"
	TargetChallenge TargetType = "challenge"
	TargetAdapter   TargetType = "adapter"
)

type Identity struct {
	ID          string            `json:"id"`
	Username    string            `json:"username"`
	DisplayName string            `json:"display_name,omitempty"`
	Type        IdentityType      `json:"type"`
	Groups      []string          `json:"groups,omitempty"`
	Email       string            `json:"email,omitempty"`
	Privileged  bool              `json:"privileged"`
	UsualGeo    string            `json:"usual_geo,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type Device struct {
	ID         string    `json:"id"`
	IdentityID string    `json:"identity_id"`
	Name       string    `json:"name"`
	Managed    bool      `json:"managed"`
	Compliant  bool      `json:"compliant"`
	SecretHash string    `json:"-"`
	CreatedAt  time.Time `json:"created_at"`
}

type Resource struct {
	ID          string      `json:"id"`
	Type        string      `json:"type"`
	Name        string      `json:"name"`
	Sensitivity Sensitivity `json:"sensitivity"`
}

type Adapter struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	TokenHash string    `json:"-"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type Policy struct {
	ID          string          `json:"id"`
	Description string          `json:"description,omitempty"`
	Enabled     bool            `json:"enabled"`
	Priority    int             `json:"priority"`
	Effect      Decision        `json:"effect"`
	Conditions  json.RawMessage `json:"conditions"`
	Challenge   *ChallengeSpec  `json:"challenge,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

type ChallengeSpec struct {
	Methods []MFAMethod `json:"methods"`
}

type AccessRequest struct {
	Identity AccessIdentity `json:"identity"`
	Resource AccessResource `json:"resource"`
	Protocol AccessProtocol `json:"protocol"`
	Source   AccessSource   `json:"source"`
	Device   AccessDevice   `json:"device"`
	Context  AccessContext  `json:"context"`
}

type AccessIdentity struct {
	Username             string   `json:"username"`
	Groups               []string `json:"groups,omitempty"`
	Type                 string   `json:"type"`
	Privileged           bool     `json:"privileged,omitempty"`
	UsualGeo             string   `json:"usual_geo,omitempty"`
	LastLogonDays        int      `json:"last_logon_days,omitempty"`
	PasswordNeverExpires bool     `json:"password_never_expires,omitempty"`
	HasSPN               bool     `json:"has_spn,omitempty"`
	IsGMSA               bool     `json:"is_gmsa,omitempty"`
}

type AccessResource struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Sensitivity string `json:"sensitivity"`
}

type AccessProtocol struct {
	Name string `json:"name"`
}

type AccessSource struct {
	IP         string `json:"ip,omitempty"`
	Geo        string `json:"geo,omitempty"`
	Reputation string `json:"reputation,omitempty"`
}

type AccessDevice struct {
	Managed   bool `json:"managed"`
	Compliant bool `json:"compliant"`
}

type AccessContext struct {
	MFARecent         bool `json:"mfa_recent"`
	Interactive       bool `json:"interactive"`
	BaselineDeviation bool `json:"baseline_deviation"`
}

type AccessDecision struct {
	RequestID string         `json:"request_id"`
	Decision  Decision       `json:"decision"`
	RiskScore int            `json:"risk_score"`
	Reasons   []string       `json:"reasons"`
	Challenge *ChallengeInfo `json:"challenge,omitempty"`
}

type ChallengeInfo struct {
	ID        string      `json:"id"`
	Methods   []MFAMethod `json:"methods"`
	ExpiresAt time.Time   `json:"expires_at"`
}

type Challenge struct {
	ID          string          `json:"id"`
	IdentityID  string          `json:"identity_id"`
	RequestID   string          `json:"request_id"`
	Methods     []MFAMethod     `json:"methods"`
	Status      ChallengeStatus `json:"status"`
	PushNumber  int             `json:"push_number,omitempty"`
	Nonce       string          `json:"-"`
	Attempts    int             `json:"attempts"`
	MaxAttempts int             `json:"max_attempts"`
	ExpiresAt   time.Time       `json:"expires_at"`
	CreatedAt   time.Time       `json:"created_at"`
	ResolvedAt  *time.Time      `json:"resolved_at,omitempty"`
}

type Factor struct {
	ID         string       `json:"id"`
	IdentityID string       `json:"identity_id"`
	Method     MFAMethod    `json:"method"`
	Status     FactorStatus `json:"status"`
	Secret     string       `json:"-"`
	CreatedAt  time.Time    `json:"created_at"`
}

type AuthToken struct {
	ID        string     `json:"id"`
	TokenHash string     `json:"-"`
	Role      Role       `json:"role"`
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Revoked   bool       `json:"revoked"`
	CreatedAt time.Time  `json:"created_at"`
}

type AuditEvent struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	Type         string                 `json:"type"`
	Actor        AuditActor             `json:"actor"`
	Target       AuditTarget            `json:"target"`
	Decision     Decision               `json:"decision,omitempty"`
	RiskScore    int                    `json:"risk_score,omitempty"`
	Reasons      []string               `json:"reasons,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	PreviousHash string                 `json:"previous_hash"`
	Hash         string                 `json:"hash"`
}

type AuditActor struct {
	Type ActorType `json:"type"`
	ID   string    `json:"id"`
}

type AuditTarget struct {
	Type TargetType `json:"type"`
	ID   string     `json:"id"`
}

type RiskResult struct {
	Score   int      `json:"score"`
	Level   string   `json:"level"`
	Reasons []string `json:"reasons"`
}

type PolicyDecision struct {
	Effect    Decision       `json:"effect"`
	PolicyID  string         `json:"policy_id"`
	Reasons   []string       `json:"reasons"`
	Challenge *ChallengeSpec `json:"challenge,omitempty"`
}

func NewID() string {
	return uuid.New().String()
}

type ADAuthEvent struct {
	EventID       int       `json:"event_id"`
	Timestamp     time.Time `json:"timestamp"`
	AccountName   string    `json:"account_name"`
	AccountDomain string    `json:"account_domain"`
	AccountSID    string    `json:"account_sid"`
	LogonType     int       `json:"logon_type"`
	LogonProcess  string    `json:"logon_process"`
	AuthPackage   string    `json:"auth_package"`
	SourceIP      string    `json:"source_ip"`
	SourcePort    int       `json:"source_port"`
	TargetServer  string    `json:"target_server"`
	TargetSPN     string    `json:"target_spn"`
	Status        string    `json:"status"`
	SubStatus     string    `json:"sub_status"`
	DCName        string    `json:"dc_name"`
	EventType     string    `json:"event_type"`
}

type ADAuthEventBatch struct {
	Events []ADAuthEvent `json:"events"`
}

type ADEventDecision struct {
	AccountSID  string   `json:"account_sid"`
	AccountName string   `json:"account_name"`
	Decision    Decision `json:"decision"`
	RiskScore   int      `json:"risk_score"`
	Reasons     []string `json:"reasons"`
}

type ADAuthEventBatchResponse struct {
	Accepted  int               `json:"accepted"`
	Decisions []ADEventDecision `json:"decisions"`
}

type ADInventoryRecord struct {
	SID                string    `json:"sid"`
	SamAccountName     string    `json:"sam_account_name"`
	DisplayName        string    `json:"display_name"`
	ObjectClass        string    `json:"object_class"`
	UserAccountControl int       `json:"user_account_control"`
	SPNs               []string  `json:"spns,omitempty"`
	MemberOf           []string  `json:"member_of,omitempty"`
	LastLogonTimestamp time.Time `json:"last_logon_timestamp"`
	PwdLastSet         time.Time `json:"pwd_last_set"`
	Enabled            bool      `json:"enabled"`
	OU                 string    `json:"ou"`
	IsGMSA             bool      `json:"is_gmsa"`
	IsPrivileged       bool      `json:"is_privileged"`
}

type ADInventorySummary struct {
	TotalAccounts      int       `json:"total_accounts"`
	UserAccounts       int       `json:"user_accounts"`
	ComputerAccounts   int       `json:"computer_accounts"`
	ServiceAccounts    int       `json:"service_accounts"`
	PrivilegedAccounts int       `json:"privileged_accounts"`
	StaleAccounts      int       `json:"stale_accounts"`
	DisabledAccounts   int       `json:"disabled_accounts"`
	ScannedAt          time.Time `json:"scanned_at"`
}

type TimeWindow struct {
	StartMinuteOfDay int   `json:"start_minute_of_day"`
	EndMinuteOfDay   int   `json:"end_minute_of_day"`
	DaysOfWeek       []int `json:"days_of_week"`
}

type ServiceAccountBaseline struct {
	AllowedSourceIPs   []string     `json:"allowed_source_ips"`
	AllowedTargetSPNs  []string     `json:"allowed_target_spns"`
	AllowedLogonTypes  []int        `json:"allowed_logon_types"`
	AllowedTimeWindows []TimeWindow `json:"allowed_time_windows"`
	AllowedProtocols   []string     `json:"allowed_protocols"`
}

type BehaviouralProfile struct {
	AccountSID          string                  `json:"account_sid"`
	SamAccountName      string                  `json:"sam_account_name"`
	ObservationStart    time.Time               `json:"observation_start"`
	ObservationEnd      time.Time               `json:"observation_end"`
	TotalAuthCount      int                     `json:"total_auth_count"`
	TimeOfDayHistogram  [24]int                 `json:"time_of_day_histogram"`
	DayOfWeekHistogram  [7]int                  `json:"day_of_week_histogram"`
	SourceIPs           map[string]int          `json:"source_ips"`
	TargetSPNs          map[string]int          `json:"target_spns"`
	LogonTypes          map[int]int             `json:"logon_types"`
	AuthPackages        map[string]int          `json:"auth_packages"`
	LastEventTime       time.Time               `json:"last_event_time"`
	InterArrivalSum     float64                 `json:"inter_arrival_sum"`
	InterArrivalSumSq   float64                 `json:"inter_arrival_sum_sq"`
	InterArrivalCount   int                     `json:"inter_arrival_count"`
	ClassificationScore float64                 `json:"classification_score"`
	Classified          bool                    `json:"classified"`
	ClassifiedAt        time.Time               `json:"classified_at"`
	Baseline            *ServiceAccountBaseline `json:"baseline,omitempty"`
}
