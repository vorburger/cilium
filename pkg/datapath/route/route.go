// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package route

import (
	"net"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"

	"github.com/vishvananda/netlink"
)

type Route struct {
	Prefix  net.IPNet
	Nexthop *net.IP
	Local   net.IP
	Device  string
	MTU     int
	Proto   int
	Scope   netlink.Scope
	Table   int
	Type    int
}

func (r *Route) getLogger() *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"prefix":            r.Prefix,
		"nexthop":           r.Nexthop,
		"local":             r.Local,
		logfields.Interface: r.Device,
	})
}

// ByMask is used to sort an array of routes by mask, narrow first.
type ByMask []Route

func (a ByMask) Len() int {
	return len(a)
}

func (a ByMask) Less(i, j int) bool {
	lenA, _ := a[i].Prefix.Mask.Size()
	lenB, _ := a[j].Prefix.Mask.Size()
	return lenA > lenB
}

func (a ByMask) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
