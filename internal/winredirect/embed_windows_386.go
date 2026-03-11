package winredirect

import _ "embed"

//go:embed x86/winredirect.sys
var driverContent []byte
