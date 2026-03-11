package tun

import "context"

// AutoRedirectMetadata carries process info obtained cheaply at redirect time.
// On Windows, WFP classify provides PID for free; Go resolves path from PID.
// This replaces the expensive process finder (netlink diag / sysctl / GetExtendedTcpTable)
// used in sing-box when process-based routing rules are configured.
type AutoRedirectMetadata struct {
	ProcessID   uint32
	ProcessPath string
	UserId      int32 // -1 if unknown
}

type autoRedirectMetadataKey struct{}

func ContextWithAutoRedirectMetadata(ctx context.Context, metadata *AutoRedirectMetadata) context.Context {
	return context.WithValue(ctx, autoRedirectMetadataKey{}, metadata)
}

func AutoRedirectMetadataFromContext(ctx context.Context) *AutoRedirectMetadata {
	metadata, _ := ctx.Value(autoRedirectMetadataKey{}).(*AutoRedirectMetadata)
	return metadata
}
