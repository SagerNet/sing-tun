package winredirect

import _ "embed"

//go:embed amd64/winredirect.sys
var driverContent []byte
