package winredirect

import _ "embed"

//go:embed arm64/winredirect.sys
var driverContent []byte
