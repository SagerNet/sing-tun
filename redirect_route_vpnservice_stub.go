//go:build linux && !android

package tun

func (r *autoRedirect) setupAndroidVPNServiceRules() error {
	return nil
}

func (r *autoRedirect) updateAndroidVPNServiceRules() error {
	return nil
}

func (r *autoRedirect) cleanupAndroidVPNServiceRules() {
}

func (r *autoRedirect) setupBypassRoute() {
}

func (r *autoRedirect) updateBypassRoute() error {
	return nil
}

func (r *autoRedirect) cleanupBypassRoute() {
}

func (r *autoRedirect) UpdateRouteAddressSet() error {
	return nil
}
