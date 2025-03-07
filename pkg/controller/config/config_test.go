/*
 * Copyright The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {
	os.Setenv("INSTANCE_IP", "10.244.0.81")
	os.Setenv("POD_NAME", "test")
	os.Setenv("POD_NAMESPACE", "testNs")
	os.Setenv("XDS_ADDRESS", "istiod.istio-system.svc:15012")
	config := GetConfig("ads")
	assert.Equal(t, "sidecar~10.244.0.81~test.testNs~testNs.svc.cluster.local", config.ServiceNode)
	assert.Equal(t, "istiod.istio-system.svc:15012", config.DiscoveryAddress)
}
