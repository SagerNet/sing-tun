package tun

import (
	"context"
	"sort"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ranges"
)

const (
	androidUserRange        = 100000
	userEnd          uint32 = 0xFFFFFFFF - 1
)

func (o *Options) BuildAndroidRules(packageManager PackageManager, errorHandler E.Handler) {
	if len(o.IncludeAndroidUser) > 0 {
		o.IncludeAndroidUser = common.Uniq(o.IncludeAndroidUser)
		sort.Ints(o.IncludeAndroidUser)
		for _, androidUser := range o.IncludeAndroidUser {
			o.IncludeUID = append(o.IncludeUID, ranges.New[uint32](uint32(androidUser)*androidUserRange, uint32(androidUser+1)*androidUserRange-1))
		}
	}
	if len(o.IncludePackage) > 0 {
		o.IncludePackage = common.Uniq(o.IncludePackage)
		for _, packageName := range o.IncludePackage {
			if sharedId, loaded := packageManager.IDBySharedPackage(packageName); loaded {
				o.IncludeUID = append(o.IncludeUID, ranges.NewSingle(sharedId))
				continue
			}
			if ids, loaded := packageManager.IDByPackage(packageName); loaded {
				for _, id := range ids {
					o.IncludeUID = append(o.IncludeUID, ranges.NewSingle(id))
				}
				continue
			}
			errorHandler.NewError(context.Background(), E.New("package to include not found: ", packageName))
		}
	}
	if len(o.ExcludePackage) > 0 {
		o.ExcludePackage = common.Uniq(o.ExcludePackage)
		for _, packageName := range o.ExcludePackage {
			if sharedId, loaded := packageManager.IDBySharedPackage(packageName); loaded {
				o.ExcludeUID = append(o.ExcludeUID, ranges.NewSingle(sharedId))
				continue
			}
			if ids, loaded := packageManager.IDByPackage(packageName); loaded {
				for _, id := range ids {
					o.ExcludeUID = append(o.ExcludeUID, ranges.NewSingle(id))
				}
				continue
			}
			errorHandler.NewError(context.Background(), E.New("package to exclude not found: ", packageName))
		}
	}
}

func (o *Options) ExcludedRanges() (uidRanges []ranges.Range[uint32]) {
	return buildExcludedRanges(o.IncludeUID, o.ExcludeUID)
}

func buildExcludedRanges(includeRanges []ranges.Range[uint32], excludeRanges []ranges.Range[uint32]) (uidRanges []ranges.Range[uint32]) {
	uidRanges = includeRanges
	if len(uidRanges) > 0 {
		uidRanges = ranges.Exclude(uidRanges, excludeRanges)
		uidRanges = ranges.Revert(0, userEnd, uidRanges)
	} else {
		uidRanges = excludeRanges
	}
	return ranges.Merge(uidRanges)
}
