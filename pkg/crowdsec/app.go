// Copyright 2020 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crowdsec

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CrowdSec{})
	//httpcaddyfile.RegisterHandlerDirective("crowdsec_handler", parseCaddyfile)
}

// CaddyModule returns the Caddy module information.
func (CrowdSec) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "crowdsec",
		New: func() caddy.Module { return new(CrowdSec) },
	}
}

// CrowdSec is a Caddy App that functions as a CrowdSec bouncer
type CrowdSec struct {
	APIKey         string `json:"api_key"`
	APIUrl         string `json:"api_url,omitempty"`
	TickerInterval string `json:"ticker_interval,omitempty"`

	ctx     caddy.Context
	logger  *zap.Logger
	bouncer *Bouncer
}

// Provision sets up the OpenAPI Validator responder.
func (c *CrowdSec) Provision(ctx caddy.Context) error {

	c.processDefaults()

	c.ctx = ctx
	c.logger = ctx.Logger(c)
	defer c.logger.Sync()

	bouncer, err := NewBouncer(c.APIKey, c.APIUrl, c.TickerInterval, c.logger)
	if err != nil {
		return err
	}

	if err := bouncer.Init(); err != nil {
		return err
	}

	c.bouncer = bouncer

	return nil
}

func (c *CrowdSec) processDefaults() {
	if c.APIUrl == "" {
		c.APIUrl = "http://127.0.0.1:8080"
	}
	if c.TickerInterval == "" {
		c.TickerInterval = "60s"
	}
}

// Validate ensures the app's configuration is valid.
func (c *CrowdSec) Validate() error {

	// TODO: fail hard after provisioning is not correct? Or do it in provisioning already?

	return nil
}

// Start starts the CrowdSec Caddy app
func (c *CrowdSec) Start() error {
	c.bouncer.Run()
	return nil
}

// Stop stops the CrowdSec Caddy app
func (c *CrowdSec) Stop() error {
	return c.bouncer.ShutDown()
}

// IsAllowed is used by the CrowdSec HTTP handler to check if
// an IP is allowed to perform a request
func (c *CrowdSec) IsAllowed(ip string) (bool, *models.Decision, error) {
	// TODO: check if running? fully loaded, etc?
	return c.bouncer.IsAllowed(ip)
}

// Interface guards
var (
	_ caddy.Module      = (*CrowdSec)(nil)
	_ caddy.App         = (*CrowdSec)(nil)
	_ caddy.Provisioner = (*CrowdSec)(nil)
	_ caddy.Validator   = (*CrowdSec)(nil)
)