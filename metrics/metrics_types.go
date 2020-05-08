package metrics

import (
	"context"
)

type SessionMetrics struct {
	Invocations     Counter
	DirectSessions  Counter
	NextSessions    Counter
	DurationGauge   Gauge
	DecisionMetrics DecisionMetrics
	ErrorMetrics    SessionErrorMetrics
}

var EmptySessionMetrics SessionMetrics = SessionMetrics{
	Invocations:     &EmptyCounter{},
	DirectSessions:  &EmptyCounter{},
	NextSessions:    &EmptyCounter{},
	DurationGauge:   &EmptyGauge{},
	DecisionMetrics: EmptyDecisionMetrics,
	ErrorMetrics:    EmptySessionErrorMetrics,
}

type SessionErrorMetrics struct {
	UnserviceableUpdate         Counter
	ReadPacketFailure           Counter
	FallbackToDirect            Counter
	EarlyFallbackToDirect       Counter
	PipelineExecFailure         Counter
	GetServerDataFailure        Counter
	UnmarshalServerDataFailure  Counter
	GetSessionDataFailure       Counter
	UnmarshalSessionDataFailure Counter
	BuyerNotFound               Counter
	VerifyFailure               Counter
	OldSequence                 Counter
	WriteCachedResponseFailure  Counter
	ClientLocateFailure         Counter
	NearRelaysLocateFailure     Counter
	NoRelaysInDatacenter        Counter
	RouteFailure                Counter
	EncryptionFailure           Counter
	WriteResponseFailure        Counter
	UpdateSessionFailure        Counter
	BillingFailure              Counter
}

var EmptySessionErrorMetrics SessionErrorMetrics = SessionErrorMetrics{
	UnserviceableUpdate:         &EmptyCounter{},
	ReadPacketFailure:           &EmptyCounter{},
	FallbackToDirect:            &EmptyCounter{},
	EarlyFallbackToDirect:       &EmptyCounter{},
	PipelineExecFailure:         &EmptyCounter{},
	GetServerDataFailure:        &EmptyCounter{},
	UnmarshalServerDataFailure:  &EmptyCounter{},
	GetSessionDataFailure:       &EmptyCounter{},
	UnmarshalSessionDataFailure: &EmptyCounter{},
	BuyerNotFound:               &EmptyCounter{},
	VerifyFailure:               &EmptyCounter{},
	OldSequence:                 &EmptyCounter{},
	WriteCachedResponseFailure:  &EmptyCounter{},
	ClientLocateFailure:         &EmptyCounter{},
	NearRelaysLocateFailure:     &EmptyCounter{},
	NoRelaysInDatacenter:        &EmptyCounter{},
	RouteFailure:                &EmptyCounter{},
	EncryptionFailure:           &EmptyCounter{},
	WriteResponseFailure:        &EmptyCounter{},
	UpdateSessionFailure:        &EmptyCounter{},
	BillingFailure:              &EmptyCounter{},
}

type DecisionMetrics struct {
	NoReason            Counter
	ForceDirect         Counter
	ForceNext           Counter
	NoNextRoute         Counter
	ABTestDirect        Counter
	RTTReduction        Counter
	PacketLossMultipath Counter
	JitterMultipath     Counter
	VetoRTT             Counter
	RTTMultipath        Counter
	VetoPacketLoss      Counter
	FallbackToDirect    Counter
	VetoYOLO            Counter
	InitialSlice        Counter
	VetoRTTYOLO         Counter
	VetoPacketLossYOLO  Counter
	RTTHysteresis       Counter
	VetoCommit          Counter
}

var EmptyDecisionMetrics DecisionMetrics = DecisionMetrics{
	NoReason:            &EmptyCounter{},
	ForceDirect:         &EmptyCounter{},
	ForceNext:           &EmptyCounter{},
	NoNextRoute:         &EmptyCounter{},
	ABTestDirect:        &EmptyCounter{},
	RTTReduction:        &EmptyCounter{},
	PacketLossMultipath: &EmptyCounter{},
	JitterMultipath:     &EmptyCounter{},
	VetoRTT:             &EmptyCounter{},
	RTTMultipath:        &EmptyCounter{},
	VetoPacketLoss:      &EmptyCounter{},
	FallbackToDirect:    &EmptyCounter{},
	VetoYOLO:            &EmptyCounter{},
	InitialSlice:        &EmptyCounter{},
	VetoRTTYOLO:         &EmptyCounter{},
	VetoPacketLossYOLO:  &EmptyCounter{},
	RTTHysteresis:       &EmptyCounter{},
	VetoCommit:          &EmptyCounter{},
}

type ServerInitMetrics struct {
	Invocations   Counter
	DurationGauge Gauge
	ErrorMetrics  ServerInitErrorMetrics
}

var EmptyServerInitMetrics ServerInitMetrics = ServerInitMetrics{
	Invocations:   &EmptyCounter{},
	DurationGauge: &EmptyGauge{},
	ErrorMetrics:  EmptyServerInitErrorMetrics,
}

type ServerInitErrorMetrics struct {
	UnmarshalFailure    Counter
	SDKTooOld           Counter
	BuyerNotFound       Counter
	VerificationFailure Counter
	DatacenterNotFound  Counter
}

var EmptyServerInitErrorMetrics ServerInitErrorMetrics = ServerInitErrorMetrics{
	UnmarshalFailure:    &EmptyCounter{},
	SDKTooOld:           &EmptyCounter{},
	BuyerNotFound:       &EmptyCounter{},
	DatacenterNotFound:  &EmptyCounter{},
	VerificationFailure: &EmptyCounter{},
}

type ServerUpdateMetrics struct {
	Invocations   Counter
	DurationGauge Gauge
	ErrorMetrics  ServerUpdateErrorMetrics
}

var EmptyServerUpdateMetrics ServerUpdateMetrics = ServerUpdateMetrics{
	Invocations:   &EmptyCounter{},
	DurationGauge: &EmptyGauge{},
	ErrorMetrics:  EmptyServerUpdateErrorMetrics,
}

type ServerUpdateErrorMetrics struct {
	UnserviceableUpdate  Counter
	UnmarshalFailure     Counter
	SDKTooOld            Counter
	BuyerNotFound        Counter
	DatacenterNotFound   Counter
	VerificationFailure  Counter
	PacketSequenceTooOld Counter
}

var EmptyServerUpdateErrorMetrics ServerUpdateErrorMetrics = ServerUpdateErrorMetrics{
	UnserviceableUpdate:  &EmptyCounter{},
	UnmarshalFailure:     &EmptyCounter{},
	SDKTooOld:            &EmptyCounter{},
	BuyerNotFound:        &EmptyCounter{},
	DatacenterNotFound:   &EmptyCounter{},
	VerificationFailure:  &EmptyCounter{},
	PacketSequenceTooOld: &EmptyCounter{},
}

type RelayInitMetrics struct {
	Invocations   Counter
	DurationGauge Gauge
	ErrorMetrics  RelayInitErrorMetrics
}

var EmptyRelayInitMetrics RelayInitMetrics = RelayInitMetrics{
	Invocations:   &EmptyCounter{},
	DurationGauge: &EmptyGauge{},
	ErrorMetrics:  EmptyRelayInitErrorMetrics,
}

type RelayInitErrorMetrics struct {
	UnmarshalFailure   Counter
	InvalidMagic       Counter
	InvalidVersion     Counter
	RelayNotFound      Counter
	DecryptionFailure  Counter
	RedisFailure       Counter
	RelayAlreadyExists Counter
	IPLookupFailure    Counter
}

var EmptyRelayInitErrorMetrics RelayInitErrorMetrics = RelayInitErrorMetrics{
	UnmarshalFailure:   &EmptyCounter{},
	InvalidMagic:       &EmptyCounter{},
	InvalidVersion:     &EmptyCounter{},
	RelayNotFound:      &EmptyCounter{},
	DecryptionFailure:  &EmptyCounter{},
	RedisFailure:       &EmptyCounter{},
	RelayAlreadyExists: &EmptyCounter{},
	IPLookupFailure:    &EmptyCounter{},
}

type RelayUpdateMetrics struct {
	Invocations   Counter
	DurationGauge Gauge
	ErrorMetrics  RelayUpdateErrorMetrics
}

var EmptyRelayUpdateMetrics RelayUpdateMetrics = RelayUpdateMetrics{
	Invocations:   &EmptyCounter{},
	DurationGauge: &EmptyGauge{},
	ErrorMetrics:  EmptyRelayUpdateErrorMetrics,
}

type RelayUpdateErrorMetrics struct {
	UnmarshalFailure      Counter
	InvalidVersion        Counter
	ExceedMaxRelays       Counter
	RedisFailure          Counter
	RelayNotFound         Counter
	RelayUnmarshalFailure Counter
	InvalidToken          Counter
}

var EmptyRelayUpdateErrorMetrics RelayUpdateErrorMetrics = RelayUpdateErrorMetrics{
	UnmarshalFailure:      &EmptyCounter{},
	InvalidVersion:        &EmptyCounter{},
	ExceedMaxRelays:       &EmptyCounter{},
	RedisFailure:          &EmptyCounter{},
	RelayNotFound:         &EmptyCounter{},
	RelayUnmarshalFailure: &EmptyCounter{},
	InvalidToken:          &EmptyCounter{},
}

type RelayHandlerMetrics struct {
	Invocations   Counter
	DurationGauge Gauge
	ErrorMetrics  RelayHandlerErrorMetrics
}

var EmptyRelayHandlerMetrics RelayHandlerMetrics = RelayHandlerMetrics{
	Invocations:   &EmptyCounter{},
	DurationGauge: &EmptyGauge{},
	ErrorMetrics:  EmptyRelayHandlerErrorMetrics,
}

type RelayHandlerErrorMetrics struct {
	UnmarshalFailure      Counter
	ExceedMaxRelays       Counter
	RelayNotFound         Counter
	NoAuthHeader          Counter
	BadAuthHeaderLength   Counter
	BadAuthHeaderToken    Counter
	BadNonce              Counter
	BadEncryptedAddress   Counter
	DecryptFailure        Counter
	RedisFailure          Counter
	RelayUnmarshalFailure Counter
}

var EmptyRelayHandlerErrorMetrics RelayHandlerErrorMetrics = RelayHandlerErrorMetrics{
	UnmarshalFailure:      &EmptyCounter{},
	ExceedMaxRelays:       &EmptyCounter{},
	RelayNotFound:         &EmptyCounter{},
	NoAuthHeader:          &EmptyCounter{},
	BadAuthHeaderLength:   &EmptyCounter{},
	BadAuthHeaderToken:    &EmptyCounter{},
	BadNonce:              &EmptyCounter{},
	BadEncryptedAddress:   &EmptyCounter{},
	DecryptFailure:        &EmptyCounter{},
	RedisFailure:          &EmptyCounter{},
	RelayUnmarshalFailure: &EmptyCounter{},
}

type RelayStatMetrics struct {
	NumRelays Gauge
	NumRoutes Gauge
}

var EmptyRelayStatMetrics RelayStatMetrics = RelayStatMetrics{
	NumRelays: &EmptyGauge{},
	NumRoutes: &EmptyGauge{},
}

func NewSessionMetrics(ctx context.Context, metricsHandler Handler) (*SessionMetrics, error) {
	var err error

	sessionMetrics := SessionMetrics{}

	sessionMetrics.Invocations, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Total session update invocations",
		ServiceName: "server_backend",
		ID:          "session.count",
		Unit:        "invocations",
		Description: "The total number of concurrent sessions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DirectSessions, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Total direct session count",
		ServiceName: "server_backend",
		ID:          "session.direct.count",
		Unit:        "sessions",
		Description: "The total number of sessions that are currently being served a direct route",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.NextSessions, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Total next session count",
		ServiceName: "server_backend",
		ID:          "session.next.count",
		Unit:        "sessions",
		Description: "The total number of sessions that are currently being served a network next route",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DurationGauge, err = metricsHandler.NewGauge(ctx, &Descriptor{
		DisplayName: "Session update duration",
		ServiceName: "server_backend",
		ID:          "session.duration",
		Unit:        "milliseconds",
		Description: "How long it takes to process a session update request",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.NoReason, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision no reason",
		ServiceName: "server_backend",
		ID:          "session.route_decision.no_reason",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.ForceDirect, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision force direct",
		ServiceName: "server_backend",
		ID:          "session.route_decision.force_direct",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.ForceNext, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision force next",
		ServiceName: "server_backend",
		ID:          "session.route_decision.force_next",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.NoNextRoute, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision no next route",
		ServiceName: "server_backend",
		ID:          "session.route_decision.no_next_route",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.ABTestDirect, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision AB test direct",
		ServiceName: "server_backend",
		ID:          "session.route_decision.ab_test_direct",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.RTTReduction, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision RTT reduction",
		ServiceName: "server_backend",
		ID:          "session.route_decision.rtt_reduction",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.PacketLossMultipath, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision packet loss multipath",
		ServiceName: "server_backend",
		ID:          "session.route_decision.packet_loss_multipath",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.JitterMultipath, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision jitter multipath",
		ServiceName: "server_backend",
		ID:          "session.route_decision.jitter_multipath",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.VetoRTT, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision veto RTT",
		ServiceName: "server_backend",
		ID:          "session.route_decision.veto_rtt",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.RTTMultipath, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision RTT multipath",
		ServiceName: "server_backend",
		ID:          "session.route_decision.rtt_multipath",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.VetoPacketLoss, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision veto packet loss",
		ServiceName: "server_backend",
		ID:          "session.route_decision.veto_packet_loss",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.FallbackToDirect, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision fallback to direct",
		ServiceName: "server_backend",
		ID:          "session.route_decision.fallback_to_direct",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.VetoYOLO, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision veto YOLO",
		ServiceName: "server_backend",
		ID:          "session.route_decision.veto_yolo",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.InitialSlice, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision initial slice",
		ServiceName: "server_backend",
		ID:          "session.route_decision.initial_slice",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.VetoRTTYOLO, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision veto RTT YOLO",
		ServiceName: "server_backend",
		ID:          "session.route_decision.veto_rtt_yolo",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.VetoPacketLossYOLO, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision veto packet loss yolo",
		ServiceName: "server_backend",
		ID:          "session.route_decision.veto_packet_loss_yolo",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.RTTHysteresis, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision RTT hysteresis",
		ServiceName: "server_backend",
		ID:          "session.route_decision.rtt_hysteresis",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.DecisionMetrics.VetoCommit, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Decision veto commit",
		ServiceName: "server_backend",
		ID:          "session.route_decision.veto_commit",
		Unit:        "decisions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.UnserviceableUpdate, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Unserviceable Session Updates",
		ServiceName: "server_backend",
		ID:          "session.error.unserviceable_sessions",
		Unit:        "sessions",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.BillingFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Billing Failure",
		ServiceName: "server_backend",
		ID:          "session.error.billing_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.BuyerNotFound, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Buyer Not Found",
		ServiceName: "server_backend",
		ID:          "session.error.buyer_not_found",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.ClientLocateFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Client Locate Failure",
		ServiceName: "server_backend",
		ID:          "session.error.client_locate_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.EncryptionFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Encryption Failure",
		ServiceName: "server_backend",
		ID:          "session.error.encryption_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.FallbackToDirect, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Fallback To Direct",
		ServiceName: "server_backend",
		ID:          "session.error.fallback_to_direct",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.EarlyFallbackToDirect, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Early Fallback To Direct",
		ServiceName: "server_backend",
		ID:          "session.error.early_fallback_to_direct",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.GetServerDataFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Get Server Data Failure",
		ServiceName: "server_backend",
		ID:          "session.error.get_server_data_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.GetSessionDataFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Get Session Data Failure",
		ServiceName: "server_backend",
		ID:          "session.error.get_session_data_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.NearRelaysLocateFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Near Relays Locate Failure",
		ServiceName: "server_backend",
		ID:          "session.error.near_relays_locate_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.NoRelaysInDatacenter, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session No Relays In Datacenter",
		ServiceName: "server_backend",
		ID:          "session.error.no_relays_in_datacenter",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.OldSequence, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Old Sequence",
		ServiceName: "server_backend",
		ID:          "session.error.old_sequence",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.PipelineExecFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Redis Pipeline Exec Failure",
		ServiceName: "server_backend",
		ID:          "session.error.redis_pipeline_exec_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.ReadPacketFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Read Packet Failure",
		ServiceName: "server_backend",
		ID:          "session.error.read_packet_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.RouteFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Route Failure",
		ServiceName: "server_backend",
		ID:          "session.error.route_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.UnmarshalServerDataFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Unmarshal Server Data Failure",
		ServiceName: "server_backend",
		ID:          "session.error.unmarshal_server_data_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.UnmarshalSessionDataFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Unmarshal Session Data Failure",
		ServiceName: "server_backend",
		ID:          "session.error.unmarshal_session_data_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.UpdateSessionFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Update Session Failure",
		ServiceName: "server_backend",
		ID:          "session.error.update_session_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.VerifyFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Verify Failure",
		ServiceName: "server_backend",
		ID:          "session.error.verify_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.WriteCachedResponseFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Write Cached Response Failure",
		ServiceName: "server_backend",
		ID:          "session.error.write_cached_response_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics.ErrorMetrics.WriteResponseFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Session Write Response Failure",
		ServiceName: "server_backend",
		ID:          "session.error.write_response_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	return &sessionMetrics, nil
}

func NewServerInitMetrics(ctx context.Context, metricsHandler Handler) (*ServerInitMetrics, error) {
	initDurationGauge, err := metricsHandler.NewGauge(ctx, &Descriptor{
		DisplayName: "Server init duration",
		ServiceName: "server_backend",
		ID:          "server.init.duration",
		Unit:        "milliseconds",
		Description: "How long it takes to process a server init request.",
	})
	if err != nil {
		return nil, err
	}

	initInvocationsCounter, err := metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Total server init invocations",
		ServiceName: "server_backend",
		ID:          "server.init.count",
		Unit:        "invocations",
		Description: "The total number of concurrent servers",
	})
	if err != nil {
		return nil, err
	}

	initMetrics := ServerInitMetrics{
		Invocations:   initInvocationsCounter,
		DurationGauge: initDurationGauge,
		ErrorMetrics:  EmptyServerInitErrorMetrics,
	}

	return &initMetrics, nil
}

func NewServerUpdateMetrics(ctx context.Context, metricsHandler Handler) (*ServerUpdateMetrics, error) {
	var err error

	updateMetrics := ServerUpdateMetrics{}

	updateMetrics.DurationGauge, err = metricsHandler.NewGauge(ctx, &Descriptor{
		DisplayName: "Server update duration",
		ServiceName: "server_backend",
		ID:          "server.duration",
		Unit:        "milliseconds",
		Description: "How long it takes to process a server update request.",
	})
	if err != nil {
		return nil, err
	}

	updateMetrics.Invocations, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Total server update invocations",
		ServiceName: "server_backend",
		ID:          "server.count",
		Unit:        "invocations",
		Description: "The total number of concurrent servers",
	})
	if err != nil {
		return nil, err
	}

	updateMetrics.ErrorMetrics.UnserviceableUpdate, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Unserviceable Server Updates",
		ServiceName: "server_backend",
		ID:          "server.error.unserviceable_servers",
		Unit:        "servers",
	})
	if err != nil {
		return nil, err
	}

	updateMetrics.ErrorMetrics.UnmarshalFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Server Update Unmarshal Failure",
		ServiceName: "server_backend",
		ID:          "server.error.unmarshal_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	updateMetrics.ErrorMetrics.SDKTooOld, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Server Update SDK Too Old",
		ServiceName: "server_backend",
		ID:          "server.error.sdk_too_old",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	updateMetrics.ErrorMetrics.BuyerNotFound, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Server Update Buyer Not Found",
		ServiceName: "server_backend",
		ID:          "server.error.buyer_not_found",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	updateMetrics.ErrorMetrics.DatacenterNotFound, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Server Update Datacenter Not Found",
		ServiceName: "server_backend",
		ID:          "server.error.datacenter_not_found",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	updateMetrics.ErrorMetrics.VerificationFailure, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Server Update Verification Failure",
		ServiceName: "server_backend",
		ID:          "server.error.verification_failure",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	updateMetrics.ErrorMetrics.PacketSequenceTooOld, err = metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Server Update Packet Sequence Too Old",
		ServiceName: "server_backend",
		ID:          "server.error.packet_sequence_too_old",
		Unit:        "errors",
	})
	if err != nil {
		return nil, err
	}

	return &updateMetrics, nil
}

func NewRelayInitMetrics(ctx context.Context, metricsHandler Handler) (*RelayInitMetrics, error) {
	initCount, err := metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Total relay init count",
		ServiceName: "relay_backend",
		ID:          "relay.init.count",
		Unit:        "requests",
		Description: "The total number of received relay init requests",
	})
	if err != nil {
		return nil, err
	}

	initDuration, err := metricsHandler.NewGauge(ctx, &Descriptor{
		DisplayName: "Relay init duration",
		ServiceName: "relay_backend",
		ID:          "relay.init.duration",
		Unit:        "milliseconds",
		Description: "How long it takes to process a relay init request",
	})
	if err != nil {
		return nil, err
	}

	initMetrics := RelayInitMetrics{
		Invocations:   initCount,
		DurationGauge: initDuration,
		ErrorMetrics:  EmptyRelayInitErrorMetrics,
	}

	return &initMetrics, nil
}

func NewRelayUpdateMetrics(ctx context.Context, metricsHandler Handler) (*RelayUpdateMetrics, error) {
	updateCount, err := metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Total relay update count",
		ServiceName: "relay_backend",
		ID:          "relay.update.count",
		Unit:        "requests",
		Description: "The total number of received relay update requests",
	})
	if err != nil {
		return nil, err
	}

	updateDuration, err := metricsHandler.NewGauge(ctx, &Descriptor{
		DisplayName: "Relay update duration",
		ServiceName: "relay_backend",
		ID:          "relay.update.duration",
		Unit:        "milliseconds",
		Description: "How long it takes to process a relay update request.",
	})
	if err != nil {
		return nil, err
	}

	updateMetrics := RelayUpdateMetrics{
		Invocations:   updateCount,
		DurationGauge: updateDuration,
		ErrorMetrics:  EmptyRelayUpdateErrorMetrics,
	}

	return &updateMetrics, nil
}

func NewRelayHandlerMetrics(ctx context.Context, metricsHandler Handler) (*RelayHandlerMetrics, error) {
	handlerCount, err := metricsHandler.NewCounter(ctx, &Descriptor{
		DisplayName: "Total relay handler count",
		ServiceName: "relay_backend",
		ID:          "relay.handler.count",
		Unit:        "requests",
		Description: "The total number of received relay requests",
	})
	if err != nil {
		return nil, err
	}

	handlerDuration, err := metricsHandler.NewGauge(ctx, &Descriptor{
		DisplayName: "Relay handler duration",
		ServiceName: "relay_backend",
		ID:          "relay.handler.duration",
		Unit:        "milliseconds",
		Description: "How long it takes to process a relay request",
	})
	if err != nil {
		return nil, err
	}

	handerMetrics := RelayHandlerMetrics{
		Invocations:   handlerCount,
		DurationGauge: handlerDuration,
		ErrorMetrics:  EmptyRelayHandlerErrorMetrics,
	}

	return &handerMetrics, nil
}

func NewRelayStatMetrics(ctx context.Context, metricsHandler Handler) (*RelayStatMetrics, error) {
	numRelays, err := metricsHandler.NewGauge(ctx, &Descriptor{
		DisplayName: "Relays num relays",
		ServiceName: "relay_backend",
		ID:          "relays.num.relays",
		Unit:        "relays",
		Description: "How many relays are active",
	})
	if err != nil {
		return nil, err
	}

	numRoutes, err := metricsHandler.NewGauge(ctx, &Descriptor{
		DisplayName: "Route Matrix num routes",
		ServiceName: "relay_backend",
		ID:          "route.matrix.num.routes",
		Unit:        "routes",
		Description: "How many routes are being generated",
	})
	if err != nil {
		return nil, err
	}

	statMetrics := RelayStatMetrics{
		NumRelays: numRelays,
		NumRoutes: numRoutes,
	}

	return &statMetrics, nil
}
