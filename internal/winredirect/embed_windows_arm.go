package winredirect

import _ "embed"

//go:embed arm/winredirect.sys
var driverContent []byte
