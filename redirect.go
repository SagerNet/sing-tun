package tun

import (
	"context"

	"github.com/sagernet/sing/common/logger"
)

type AutoRedirect interface {
	Start() error
	Close() error
}

type AutoRedirectOptions struct {
	TunOptions         *Options
	Context            context.Context
	Handler            Handler
	Logger             logger.Logger
	TableName          string
	DisableNFTables    bool
	CustomRedirectPort func() int
}
