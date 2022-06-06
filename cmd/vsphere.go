/*
Copyright © 2022 Kaleb Hawkins <KalebHawkins@outlook.com>

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
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vmware/govmomi/govc/cli"
	_ "github.com/vmware/govmomi/govc/device"
	_ "github.com/vmware/govmomi/govc/device/scsi"
	_ "github.com/vmware/govmomi/govc/folder"
	_ "github.com/vmware/govmomi/govc/ls"
	_ "github.com/vmware/govmomi/govc/object"
	_ "github.com/vmware/govmomi/govc/permissions"
	_ "github.com/vmware/govmomi/govc/sso/user"
	_ "github.com/vmware/govmomi/govc/vm"
	_ "github.com/vmware/govmomi/govc/vm/disk"
)

type VCenterClient struct {
	URL          string `yaml:"url"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	Insecure     string `yaml:"insecure"`
	Datacenter   string `yaml:"datacenter"`
	ResourcePool string `yaml:"resourcePool"`
	Network      string `yaml:"network"`
	Datastore    string `yaml:"datastore"`
	Folder       string `yaml:"folder"`
	Template     string `yaml:"template"`
	Cluster      string `yaml:"cluster"`
}

func (vc *VCenterClient) CreateFolder(name string) error {
	if name == "" {
		return fmt.Errorf("config.vcenter.folder cannot be nil")
	}

	rtn := runGOVC("folder.info", name)

	if rtn == 0 {
		return nil
	}

	rtn = runGOVC("folder.create", fmt.Sprintf("/%s/vm/%s", os.Getenv("GOVC_DATACENTER"), name))

	if rtn != 0 {
		return fmt.Errorf("folder '%s' could not be created in vCenter", name)
	}

	return nil
}

func (vc *VCenterClient) SetupEnv() error {
	var config = map[string]string{
		"GOVC_URL":           vc.URL,
		"GOVC_USERNAME":      vc.Username,
		"GOVC_PASSWORD":      vc.Password,
		"GOVC_INSECURE":      vc.Insecure,
		"GOVC_DATACENTER":    vc.Datacenter,
		"GOVC_RESOURCE_POOL": vc.ResourcePool,
		"GOVC_NETWORK":       vc.Network,
		"GOVC_DATASTORE":     vc.Datastore,
		"GOVC_FOLDER":        vc.Folder,
	}

	for k, v := range config {
		// fmt.Printf("%s=%s\n", k, v)
		os.Setenv(k, v)
	}

	return nil
}

func (vc *VCenterClient) SSOUserExists(name string) bool {
	userCfg := []string{
		"sso.user.id", name,
	}

	rtn := runGOVC(userCfg...)

	if rtn == 0 {
		return true
	}

	return false
}

func (vc *VCenterClient) CreateSSOUser(name, password, description string) error {
	userCfg := []string{
		"sso.user.create",
		fmt.Sprintf("-d=%s", description),
		"-p", password, name,
	}

	rtn := runGOVC(userCfg...)

	if rtn != 0 {
		return fmt.Errorf("failed to create SSO user: %s", viper.GetString("config.pcs.vcenterServiceAccount"))
	}

	return nil
}

func (vc *VCenterClient) SetPermissions(username, role, resourcePath string) error {
	permCfg := []string{
		"permissions.set", "-principal", username,
		"-role", role, resourcePath,
	}

	rtn := runGOVC(permCfg...)

	if rtn != 0 {
		return fmt.Errorf("failed to set permissions on resource: %s", resourcePath)
	}

	return nil
}

type Disk struct {
	Size      string `yaml:"size"`
	Datastore string `yaml:"datastore"`
}

type VirtualMachine struct {
	Name       string `yaml:"name"`
	Ipaddress  string `yaml:"ipaddress"`
	Cpu        string `yaml:"cpu"`
	MemoryMB   string `yaml:"memoryMB"`
	Annotation string `yaml:"annotation"`
	Netmask    string `yaml:"netmask"`
	Gateway    string `yaml:"gateway"`
	Cidr       string `yaml:"cidr"`
	Datastore  string `yaml:"datastore"`
}

func (vm *VirtualMachine) Exists() bool {
	str := captureFuncOutput(runGOVC, "find", "-type", "m", "-name", vm.Name)
	return str != ""
}

func (vm *VirtualMachine) Create(vc *VCenterClient) error {
	var cloneCmd = []string{
		"vm.clone",
		"-vm",
		vc.Template,
		"-on=false",
		fmt.Sprintf("-ds=%v", vm.Datastore),
		fmt.Sprintf("-cluster=%v", vc.Cluster),
		fmt.Sprintf("-net=%v", vc.Network),
		fmt.Sprintf("-annotation=%v", vm.Annotation),
		"-net.adapter=vmxnet3",
		fmt.Sprintf("-c=%v", vm.Cpu),
		fmt.Sprintf("-m=%v", vm.MemoryMB),
		vm.Name,
	}

	fmt.Printf("Cloning %s from template %s\n", vm.Name, vc.Template)
	rtn := runGOVC(cloneCmd...)

	if rtn == 1 {
		return fmt.Errorf("failed to clone vm %s from template %s", vm.Name, vc.Template)
	}

	return nil
}

func (vm *VirtualMachine) AddSCSI(sharing string) error {
	if sharing != "physicalSharing" && sharing != "virtualSharing" && sharing != "noSharing" {
		panic("sharing must be of type physicalSharing, virtualSharing, or noSharing")
	}

	rtn := runGOVC("device.scsi.add", "-vm", vm.Name, "-type", "pvscsi", fmt.Sprintf("-sharing=%s", sharing))

	if rtn != 0 {
		return fmt.Errorf("failed to add scsi device to %s", vm.Name)
	}

	return nil
}

func (vm *VirtualMachine) GetSCSIDevices() []string {
	rawOutut := captureFuncOutput(runGOVC, "device.ls", "-vm", vm.Name, "pvscsi-*")
	scsiDevs := strings.Split(rawOutut, "\n")
	return strings.Split(scsiDevs[:len(scsiDevs)-1][1], " ")
}

func (vm *VirtualMachine) CreateDisk(name, size, controller, datastore string) error {
	// rawOutut := captureFuncOutput(runGOVC, "device.ls", "-vm", vm.Name, "pvscsi-*")
	// scsiDevs := strings.Split(rawOutut, "\n")
	// targetScsi := strings.Split(scsiDevs[:len(scsiDevs)-1][1], " ")[0]

	var AddDiskCfg = []string{
		"vm.disk.create",
		"-vm",
		vm.Name,
		"-name",
		fmt.Sprintf("%s/%s", vm.Name, name),
		"-size",
		size,
		"-eager",
		"-thick",
		fmt.Sprintf("-controller=%s", controller),
		"-sharing=sharingMultiWriter",
		fmt.Sprintf("-ds=%s", datastore),
	}

	rtn := runGOVC(AddDiskCfg...)

	if rtn != 0 {
		return fmt.Errorf("failed to create disk on %s", vm.Name)
	}

	return nil
}

func (vm *VirtualMachine) AttachDisk(name, controller, datastore string) error {
	// rawOutut = captureFuncOutput(runGOVC, "device.ls", "-vm", s[1].Name, "pvscsi-*")
	// scsiDevs = strings.Split(rawOutut, "\n")
	// targetScsi = strings.Split(scsiDevs[:len(scsiDevs)-1][1], " ")[0]

	var attachCfg = []string{
		"vm.disk.attach",
		"-vm",
		vm.Name,
		"-disk",
		name,
		fmt.Sprintf("-controller=%s", controller),
		fmt.Sprintf("-ds=%s", datastore),
		"-link=false",
		"-mode=persistent",
		"-sharing=sharingMultiWriter",
	}

	rtn := runGOVC(attachCfg...)

	if rtn != 0 {
		return fmt.Errorf("failed to attach disk to %s", vm.Name)
	}

	return nil
}

func (vm *VirtualMachine) ConfigureNetwork(dnsServers, dnsSuffix []string) error {
	netCfg := []string{
		"vm.customize",
		"-vm",
		vm.Name,
		"-ip",
		vm.Ipaddress,
		"-netmask",
		vm.Netmask,
		"-gateway",
		vm.Gateway,
		"-dns-server",
		strings.Join(dnsServers, ","),
		"-dns-suffix",
		strings.Join(dnsSuffix, ","),
	}

	rtn := runGOVC(netCfg...)

	if rtn != 0 {
		return fmt.Errorf("failed to set ip address configuration on vm")
	}

	return nil
}

func (vm *VirtualMachine) StartConnected() error {
	connectCfg := []string{
		"device.connect",
		"-vm", vm.Name,
		"ethernet-0",
	}

	rtn := runGOVC(connectCfg...)

	if rtn != 0 {
		return fmt.Errorf("failed to set %s ethernet-0 to start connected", vm.Name)
	}

	return nil
}

func (vm *VirtualMachine) PowerOn() error {
	rtn := runGOVC("vm.power", "-on", vm.Name)

	if rtn != 0 {
		return fmt.Errorf("failed to power on %s", vm.Name)
	}

	return nil
}

func (vc *VCenterClient) Deploy() {
	err := viper.UnmarshalKey("config.vcenter", vc)
	handleErr(err)

	fmt.Println("Setting enviornment variables for GOVC...")
	vc.SetupEnv()

	fmt.Printf("Creating vCenter folder %s...\n", vc.Folder)
	err = vc.CreateFolder(vc.Folder)
	handleErr(err)

	fmt.Printf("Checking for existing user %s...\n", viper.GetString("config.pcs.vcenterServiceAccount"))
	userExists := vc.SSOUserExists(viper.GetString("config.pcs.vcenterServiceAccount"))

	if !userExists {
		fmt.Printf("Creating fencing agent user accout: %s...\n", viper.GetString("config.pcs.vcenterServiceAccount"))
		err = vc.CreateSSOUser(
			viper.GetString("config.pcs.vcenterServiceAccount"),
			viper.GetString("config.pcs.vcenterSAPassword"),
			fmt.Sprintf("User for fencing cluster %s", viper.GetString("config.pcs.clusterName")),
		)
		handleErr(err)
	}

	fmt.Printf("Setting permissions on folder %s for vcenter service account: %s\n", vc.Folder, viper.GetString("config.pcs.vcenterServiceAccount"))
	err = vc.SetPermissions(
		fmt.Sprintf("%s@vsphere.local", viper.GetString("config.pcs.vcenterServiceAccount")),
		"Admin",
		fmt.Sprintf("/%s/vm/%s", vc.Datacenter, vc.Folder),
	)
	handleErr(err)

	var VMs []*VirtualMachine
	err = viper.UnmarshalKey("config.servers", &VMs)
	handleErr(err)

	for _, srv := range VMs {
		fmt.Printf("Checking for existing server %s...\n", srv.Name)
		if srv.Exists() {
			handleErr(fmt.Errorf("virtual machine %s already exists", srv.Name))
		}
	}

	for _, srv := range VMs {
		fmt.Printf("Cloning server %s from template %s...\n", srv.Name, vc.Template)
		err = srv.Create(vc)
		handleErr(err)

		fmt.Printf("Adding scsi device to %s...\n", srv.Name)
		err = srv.AddSCSI("noSharing")
		handleErr(err)

		fmt.Printf("Setting networking configuration on %s: [IP Address: %s Gateway: %s Netmask: %s]\n", srv.Name, srv.Ipaddress, srv.Gateway, srv.Netmask)
		err = srv.ConfigureNetwork(viper.GetStringSlice("config.dns.servers"), viper.GetStringSlice("config.dns.suffix"))
		handleErr(err)
	}

	devices := VMs[0].GetSCSIDevices()
	var disk []*Disk
	err = viper.UnmarshalKey("config.appDisk", &disk)
	handleErr(err)

	fmt.Printf("Creating disk %s on %s...\n", fmt.Sprintf("%s_1001", VMs[0].Name), VMs[0].Name)
	err = VMs[0].CreateDisk(fmt.Sprintf("%s_1001", VMs[0].Name), disk[0].Size, devices[:len(devices)-1][0], disk[0].Datastore)
	handleErr(err)

	fmt.Printf("Creating second disk %s on %s...\n", fmt.Sprintf("%s_1002", VMs[0].Name), VMs[0].Name)
	err = VMs[0].CreateDisk(fmt.Sprintf("%s_1002", VMs[0].Name), disk[1].Size, devices[:len(devices)-1][0], disk[1].Datastore)
	handleErr(err)

	devices = VMs[1].GetSCSIDevices()
	fmt.Printf("Attaching disk %s to %s...\n", fmt.Sprintf("%s_1001", VMs[0].Name), VMs[1].Name)
	err = VMs[1].AttachDisk(fmt.Sprintf("%s/%s_1001", VMs[0].Name, VMs[0].Name), devices[:len(devices)-1][0], disk[0].Datastore)
	handleErr(err)

	devices = VMs[1].GetSCSIDevices()
	fmt.Printf("Attaching disk %s to %s...\n", fmt.Sprintf("%s_1002", VMs[0].Name), VMs[1].Name)
	err = VMs[1].AttachDisk(fmt.Sprintf("%s/%s_1002", VMs[0].Name, VMs[0].Name), devices[:len(devices)-1][0], disk[1].Datastore)
	handleErr(err)

	for _, srv := range VMs {
		fmt.Printf("Setting %s ethernet-0 to start connected...", srv.Name)
		err = srv.StartConnected()
		handleErr(err)

		fmt.Printf("Powering on server %s...\n", srv.Name)
		err = srv.PowerOn()
		handleErr(err)
	}
}

func runGOVC(args ...string) int {
	// fmt.Printf("Running cmd: govc %v\n", strings.Join(args, " "))
	return cli.Run(args)
}

func captureFuncOutput(f func(...string) int, args ...string) string {
	r, w, _ := os.Pipe()
	oldStdOut := os.Stdout
	os.Stdout = w

	f(args...)

	w.Close()
	out, err := ioutil.ReadAll(r)
	if err != nil {
		panic(err)
	}
	os.Stdout = oldStdOut
	r.Close()

	return string(out)
}

// vsphereCmd represents the vsphere command
var vsphereCmd = &cobra.Command{
	Use:   "vsphere",
	Short: "deploy virtual infrastructure to vsphere",
	Long: `Deploy your virtual infrastructure to
vSphere with a provided configuration file.
`,
	Run: func(cmd *cobra.Command, args []string) {
		vc := VCenterClient{}
		vc.Deploy()
	},
}

func init() {
	rootCmd.AddCommand(vsphereCmd)
}
