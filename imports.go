package crowdsec

import (
	// Import the default CrowdSec modules. Primary reason this
	// file exists is to satisfy the Caddy documentation and download
	// pages to list the modules correctly.
	_ "github.com/latomate/caddy-crowdsec-bouncer/crowdsec"
	_ "github.com/latomate/caddy-crowdsec-bouncer/http"
	_ "github.com/latomate/caddy-crowdsec-bouncer/layer4"
)
