/*
Copyright © 2022 Kaleb Hawkins <Kaleb_Hawkins@outlook.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
)

type AHVCluster struct {
	URL                  string `yaml:"url"`
	Username             string `yaml:"username"`
	Password             string `yaml:"password"`
	Template             string `yaml:"template"`
	NetworkUUID          string `yaml:"networkUUID"`
	StorageContainerUUID string `yaml:"storageContainerUUID"`
	VolumeGroup          string `yaml:"volumeGroup"`
	Insecure             bool   `yaml:"insecure"`
	URI                  string
}

type AHVVirtualMachine struct {
	Name      string `yaml:"name"`
	Cpu       string `yaml:"cpu"`
	MemoryMB  string `yaml:"memoryMB"`
	Ipaddress string `yaml:"ipaddress"`
	Netmask   string `yaml:"netmask"`
	Gateway   string `yaml:"gateway"`
	CIDR      string `yaml:"cidr"`
}

// SanitizeURL appends a trailing / to the end of the URL if there isn't one already present.
func (ahv *AHVCluster) SanitizeURL() {
	var url string

	ahv.URI = "PrismGateway/services/rest/v2.0/"

	if ahv.URL[:len(ahv.URL)-1] == "/" {
		url = ahv.URL + "PrismGateway/services/rest/v2.0/"
	} else {
		url = ahv.URL + "/"
	}

	ahv.URL = url + ahv.URI
}

func (ahv *AHVCluster) Get(Obj string) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	URL := ahv.URL + Obj

	fmt.Printf("Getting data from URL: %s\n", URL)

	req, err := http.NewRequest("GET", URL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get data from %s: %s", URL, err)
	}

	req.Header.Set("ContentType", "application/json")
	req.SetBasicAuth(ahv.Username, ahv.Password)
	resp, err := client.Do(req)

	var bodyTextStr string
	if err != nil {
		return "", fmt.Errorf("failed to get response from %s: %s", URL, err)
	} else {
		bodyText, _ := ioutil.ReadAll(resp.Body)
		bodyTextStr = string(bodyText)
	}

	return bodyTextStr, err
}

func (ahv *AHVCluster) Post(Obj string, jsonByteData []byte) (string, int, error) {
	var bodyTextStr string
	var httpCode int

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	URL := ahv.URL + Obj

	fmt.Printf("Posting data to URL: %s\n", URL)

	payloadData := bytes.NewBuffer(jsonByteData)
	req, err := http.NewRequest("POST", URL, payloadData)
	if err != nil {
		return "", 0, fmt.Errorf("failed to create new http request with payload: %s", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(ahv.Username, ahv.Password)

	resp, err := client.Do(req)

	if err != nil {
		return "", 0, fmt.Errorf("failed to get data from %s: %s", URL, err)
	} else {
		bodyText, _ := ioutil.ReadAll(resp.Body)
		httpCode = int(resp.StatusCode)
		bodyTextStr = string(bodyText)
	}

	return bodyTextStr, httpCode, err
}

// GenerateVMClonePayload payload JSON data for cloning the VM; takes clone Name as input
// Requires Network UUID of the network the Clone will be in
// Network UUID can be obtained usinag acli net.list on the CVM
func (ahv *AHVCluster) GenerateVMClonePayload(vm *AHVVirtualMachine) []byte {
	// var cloudCfg string = fmt.Sprintf(`#cloud-config
	// write_files:
	//   - path: /etc/sysconfig/network-scripts/ifcfg-ens192 content: |
	// 	DEVICE=ens192
	// 	BOOTPROTO="none"
	// 	NETMASK="%s"
	// 	IPADDR="%s"
	// 	GATEWAY="%s"
	// 	ONBOOT="yes"
	// runcmd:
	//   - [ifdown, ens192]
	//   - [ifup, ens192]`, vm.Netmask, vm.Ipaddress, vm.Gateway)

	// cloudCfgEnc := base64.StdEncoding.EncodeToString([]byte(cloudCfg))

	var postData string = fmt.Sprintf(`{
		"spec_list": [
			{
				"name": "%s",
				"memory_mb": %s,
				"num_vcpus": %s,
				"num_cores_per_vcpu": 1,
				"vm_nics": [
					{
						"adapter_type": "Vmxnet3",
						"network_uuid": "%s",
						"ip_address": "%s"
					}
				],
				"request_ip": false
			}
		]
	}`, vm.Name, vm.MemoryMB, vm.Cpu, ahv.NetworkUUID, vm.Ipaddress)

	return []byte(postData)
}

// GenerateVolumeGroupPayload generate payload JSON data for creating a VolumeGroup
func (ahv *AHVCluster) GenerateVolumeGroupPayload() []byte {
	appDiskSizeGB := viper.GetInt64("config.appDisk.sizeGB")
	appDiskSizeBytes := appDiskSizeGB * 1073741824

	var postData string = fmt.Sprintf(`{
		"description": "Used for shared disks between deviceWISE cluster nodes",
		"disk_list": [
			{
				"create_config": {
					"size": %d,
					"storage_container_uuid": "%s"
				},
				"index": 0
			},
			{
				"create_config": {
					"size": %d,
					"storage_container_uuid": "%s"
				},
				"index": 1
			}
		],
		"flash_mode_enabled": false,
		"is_hidden": false,
		"is_shared": true,
		"name": "%s"
		}`, appDiskSizeBytes, ahv.StorageContainerUUID, appDiskSizeBytes, ahv.StorageContainerUUID, ahv.VolumeGroup)

	return []byte(postData)
}

// GetVMUUID gets uuid of the VM which is to be cloned
func (ahv *AHVCluster) GetVMUUID(vmName string) (string, error) {
	vmNameUUidMap := make(map[string]string)
	vmData, err := ahv.Get("vms")

	if err != nil {
		return "", fmt.Errorf("failed to get UUID of vm %s: %s", vmName, err)
	}

	vmNameJ := gjson.Get(vmData, "entities.#.name")
	vmUuidJ := gjson.Get(vmData, "entities.#.uuid")

	for i, name := range vmNameJ.Array() {
		for j, uuid := range vmUuidJ.Array() {
			if i == j {
				vmNameUUidMap[name.String()] = uuid.String()
			}
		}
	}
	return vmNameUUidMap[vmName], err
}

// GetVolumeGroupUUID gets uuid of volume group
func (ahv *AHVCluster) GetVolumeGroupUUID(vgName string) (string, error) {
	vgNameUUidMap := make(map[string]string)
	vgData, err := ahv.Get("volume_groups")

	if err != nil {
		return "", fmt.Errorf("failed to get UUID of vg %s: %s", vgName, err)
	}

	vgNameJ := gjson.Get(vgData, "entities.#.name")
	vgUuidJ := gjson.Get(vgData, "entities.#.uuid")

	for i, name := range vgNameJ.Array() {
		for j, uuid := range vgUuidJ.Array() {
			if i == j {
				vgNameUUidMap[name.String()] = uuid.String()
			}
		}
	}
	return vgNameUUidMap[vgName], err
}

// CloneVM clones the source VM using POST v2 call to the /clone endpoint
// requires vm uuid , clone api endpoint and clone Name
func (ahv *AHVCluster) CloneVM(vm *AHVVirtualMachine, vmUuid string) (string, int) {
	cloneByteData := ahv.GenerateVMClonePayload(vm)
	peObj := "vms/" + vmUuid + "/clone"
	resp, code, _ := ahv.Post(peObj, cloneByteData)
	return resp, code
}

// CreateVolumeGroup creates a volume group given a VG Name and storageContainer ID.
func (ahv *AHVCluster) CreateVolumeGroup() (string, int) {
	createVGData := ahv.GenerateVolumeGroupPayload()
	resp, code, _ := ahv.Post("volume_groups", createVGData)
	return resp, code
}

// AttachVMToVolumeGroup attaches a VM to a volume group.
func (ahv *AHVCluster) AttachVMToVolumeGroup(vmUUID, vgUUID string) (string, int) {
	var postData string = fmt.Sprintf(`{
	"operation": "ATTACH",
	"vm_uuid": "%s"
}`, vmUUID)

	obj := "volume_groups/" + vgUUID + "/attach"
	resp, code, _ := ahv.Post(obj, []byte(postData))
	return resp, code
}

func (ahv *AHVCluster) Deploy() {
	err := viper.UnmarshalKey("config.ahv", ahv)
	handleErr(err)
	ahv.SanitizeURL()

	var Servers []*AHVVirtualMachine
	err = viper.UnmarshalKey("config.servers", &Servers)
	handleErr(err)

	templateUuid, err := ahv.GetVMUUID(ahv.Template)
	handleErr(err)

	for _, srv := range Servers {
		fmt.Printf("Cloning %s from template %s\n", srv.Name, ahv.Template)
		resp, code := ahv.CloneVM(srv, templateUuid)

		if code >= 200 && code <= 299 {
			fmt.Printf("HTTP Code %d: Clone %s created from %s\n", code, srv.Name, ahv.Template)
		} else {
			fmt.Fprintf(os.Stderr, "failed to clone virtual machine [%s] from template [%s]\n", srv.Name, ahv.Template)
			fmt.Fprintf(os.Stderr, "HTTP Code: %d refer to https://portal.nutanix.com/page/documents/details?targetId=Objects-v2_0:v20-error-responses-c.html for more information.\n", code)
			fmt.Fprintf(os.Stderr, "Response: %s\n", resp)
			os.Exit(1)
		}
	}

	fmt.Printf("Creating Volume Group: %s\n", ahv.VolumeGroup)
	resp, code := ahv.CreateVolumeGroup()

	if code >= 200 && code <= 299 {
		fmt.Printf("HTTP Code %d: Created volume group %s\n", code, ahv.VolumeGroup)
	} else {
		fmt.Fprintf(os.Stderr, "failed to create volume group %s\n", ahv.VolumeGroup)
		fmt.Fprintf(os.Stderr, "HTTP Code: %d refer to https://portal.nutanix.com/page/documents/details?targetId=Objects-v2_0:v20-error-responses-c.html for more information.\n", code)
		fmt.Fprintf(os.Stderr, "Response: %s\n", resp)
		os.Exit(1)
	}

	for _, srv := range Servers {
		fmt.Printf("Attaching virtual machine %s to volume group %s", srv.Name, ahv.VolumeGroup)
		vmUUID, err := ahv.GetVMUUID(srv.Name)
		handleErr(err)
		vgUUID, err := ahv.GetVolumeGroupUUID(ahv.VolumeGroup)
		handleErr(err)

		resp, code = ahv.AttachVMToVolumeGroup(vmUUID, vgUUID)

		if code >= 200 && code <= 299 {
			fmt.Printf("HTTP Code %d: Created volume group %s\n", code, ahv.VolumeGroup)
		} else {
			fmt.Fprintf(os.Stderr, "failed to attach virtual machine [%s] to volume group [%s]\n", srv.Name, ahv.VolumeGroup)
			fmt.Fprintf(os.Stderr, "HTTP Code: %d refer to https://portal.nutanix.com/page/documents/details?targetId=Objects-v2_0:v20-error-responses-c.html for more information.\n", code)
			fmt.Fprintf(os.Stderr, "Response: %s\n", resp)
			os.Exit(1)
		}
	}
}

// ahvCmd represents the ahv command
var ahvCmd = &cobra.Command{
	Use:   "ahv",
	Short: "deploy virtual infrastructure to ahv",
	Long: `Deploy your virtual infrastructure to
AHV with a provided configuration file.
`,
	Run: func(cmd *cobra.Command, args []string) {
		ahv := AHVCluster{}
		ahv.Deploy()
	},
}

func init() {
	rootCmd.AddCommand(ahvCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// ahvCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// ahvCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
