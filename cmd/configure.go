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
	"context"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/apenella/go-ansible/pkg/execute"
	"github.com/apenella/go-ansible/pkg/options"
	"github.com/apenella/go-ansible/pkg/playbook"
	"github.com/apenella/go-ansible/pkg/stdoutcallback/results"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// configureCmd represents the configure command
var configureCmd = &cobra.Command{
	Use:   "configure",
	Short: "configure a devicewise cluster",
	Long: `Configure the devicewise cluster with a 
provided configuration file.
`,
	Run: func(cmd *cobra.Command, args []string) {
		err := generateAnsibleVars()
		handleErr(err)

		err = generateAnsibleInv()
		handleErr(err)

		err = generatePlaybook()
		handleErr(err)

		RunPlaybook()
	},
}

func init() {
	rootCmd.AddCommand(configureCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// configureCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// configureCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

type AnsibleVars struct {
	RhelUsername           interface{} `yaml:"rhel_username"`
	RhelPassword           interface{} `yaml:"rhel_password"`
	RhelPoolIDs            []string    `yaml:"rhel_poolids"`
	DNSSuffixSearchList    []string    `yaml:"dns_suffix_search_list"`
	DomainController1      string      `yaml:"dc01"`
	DomainController2      string      `yaml:"dc02"`
	DNSServer1             string      `yaml:"dns_server1"`
	DNSServer2             string      `yaml:"dns_server2"`
	CrowdstrikeTag         string      `yaml:"crowdstrikeTag"`
	CrowdstrikeCustomerID  string      `yaml:"crowdstrikeCustomerID"`
	QualysCustomerID       string      `yaml:"qualysCustomerID"`
	QualysActivationID     string      `yaml:"qualysActivationID"`
	ClusterName            string      `yaml:"clusterName"`
	ClusterPassword        string      `yaml:"clusterPassword"`
	ClusterPasswordHash    string      `yaml:"clusterPasswordHash"`
	VirtualIP              string      `yaml:"virtualIP"`
	VCenterServer          string      `yaml:"vcenterServer,omitempty"`
	VCenterServerShortName string      `yaml:"vcenterServerShortName,omitempty"`
	VCenterServiceAccount  string      `yaml:"vcenterServiceAccount,omitempty"`
	VCenterSAPassword      string      `yaml:"vcenterSAPassword,omitempty"`
	PrimaryNode            string      `yaml:"primaryNode"`
	SecondaryNode          string      `yaml:"secondaryNode"`
	PrimaryNodeIP          string      `yaml:"primaryNodeIP"`
	SecondaryNodeIP        string      `yaml:"secondaryNodeIP"`
	PrimaryNodeGateway     string      `yaml:"primaryNodeGateway"`
	SecondaryNodeGateway   string      `yaml:"secondaryNodeGateway"`
	PrimaryNodeCIDR        string      `yaml:"primaryNodeCIDR"`
	SecondaryNodeCIDR      string      `yaml:"secondaryNodeCIDR"`
	Platform               string      `yaml:"platform"`
	SplunkUsername         string      `yaml:"splunkUsername"`
	SplunkPassword         string      `yaml:"splunkPassword"`
	SplunkDeployServer     string      `yaml:"splunkDeployServer"`
}

func generateAnsibleVars() error {
	fmt.Println("Generating Ansible variables...")
	ansVars := AnsibleVars{
		RhelUsername:           viper.GetString("config.redhat.username"),
		RhelPassword:           viper.GetString("config.redhat.password"),
		RhelPoolIDs:            viper.GetStringSlice("config.redhat.poolIDs"),
		DNSSuffixSearchList:    viper.GetStringSlice("config.dns.suffix"),
		DomainController1:      viper.GetStringSlice("config.domainControllers")[0],
		DomainController2:      viper.GetStringSlice("config.domainControllers")[1],
		DNSServer1:             viper.GetStringSlice("config.dns.servers")[0],
		DNSServer2:             viper.GetStringSlice("config.dns.servers")[1],
		CrowdstrikeTag:         viper.GetString("config.crowdstrike.tag"),
		QualysCustomerID:       viper.GetString("config.qualys.customerID"),
		QualysActivationID:     viper.GetString("config.qualys.activationID"),
		CrowdstrikeCustomerID:  viper.GetString("config.crowdstrike.customerID"),
		ClusterName:            viper.GetString("config.pcs.clusterName"),
		ClusterPassword:        viper.GetString("config.pcs.clusterPassword"),
		VirtualIP:              viper.GetString("config.pcs.virtualIP"),
		VCenterServer:          viper.GetString("config.pcs.vcenterServer"),
		VCenterServerShortName: strings.Split(viper.GetString("config.pcs.vcenterServer"), ".")[0],
		VCenterServiceAccount:  viper.GetString("config.pcs.vcenterServiceAccount"),
		VCenterSAPassword:      viper.GetString("config.pcs.vcenterSAPassword"),
		PrimaryNode:            viper.GetString("config.pcs.primaryNode"),
		SecondaryNode:          viper.GetString("config.pcs.secondaryNode"),
		SplunkUsername:         viper.GetString("config.splunk.username"),
		SplunkPassword:         viper.GetString("config.splunk.password"),
		SplunkDeployServer:     viper.GetString("config.splunk.deployServer"),
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(ansVars.ClusterPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash clusterPassword")
	}
	ansVars.ClusterPasswordHash = string(hashedPass)

	var nodes []*VirtualMachine
	err = viper.UnmarshalKey("config.servers", &nodes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal server data")
	}

	ansVars.PrimaryNodeIP = nodes[0].Ipaddress
	ansVars.SecondaryNodeIP = nodes[1].Ipaddress
	ansVars.PrimaryNodeGateway = nodes[0].Gateway
	ansVars.SecondaryNodeGateway = nodes[1].Gateway
	ansVars.PrimaryNodeCIDR = nodes[0].Cidr
	ansVars.SecondaryNodeCIDR = nodes[1].Cidr

	if k := viper.Sub("config.vcenter"); k != nil {
		ansVars.Platform = "vsphere"
	}
	if k := viper.Sub("config.ahv"); k != nil {
		ansVars.Platform = "ahv"
	}

	yml, err := yaml.Marshal(ansVars)
	if err != nil {
		return fmt.Errorf("failed to marshal ansible configuration")
	}

	err = ioutil.WriteFile("./ansible/vars.yml", yml, 0755)
	if err != nil {
		return fmt.Errorf("failed to write file ./ansible/vars.yml: %v", err)
	}

	fmt.Println("Wrote ansible variables to ./ansible/vars.yml")
	return nil
}

func generateAnsibleInv() error {
	fmt.Println("Generating ansible inventory...")
	var ansInv = `all:
  children:
    primary:
      hosts:
        %s:
    secondary:
      hosts:
        %s:
`

	var VMs []*VirtualMachine
	err := viper.UnmarshalKey("config.servers", &VMs)
	if err != nil {
		return fmt.Errorf("failed to unmarshal servers")
	}

	ansInv = fmt.Sprintf(ansInv, VMs[0].Name, VMs[1].Name)

	err = ioutil.WriteFile("./ansible/inv.yml", []byte(ansInv), 0755)
	if err != nil {
		return fmt.Errorf("failed to write file ./ansible/inv.yml: %v", err)
	}

	fmt.Println("Wrote ansible inventory to ./ansible/inv.yml")
	return nil
}

func generatePlaybook() error {
	fmt.Println("Generating playbook...")
	var plybk = `---
- hosts: primary:secondary
  gather_facts: true
  vars_files:
    - vars.yml

  roles:
    - common
    - disclaimer
    - cockpit
    - crowdstrike
    - qualys
    - splunkforwarder
    - pcs-cluster-setup
    - pcs-resource-config
    - devicewise`

	err := ioutil.WriteFile("./ansible/site.yml", []byte(plybk), 0755)
	if err != nil {
		return fmt.Errorf("failed to write file ./ansible/site.yml: %v", err)
	}

	fmt.Println("Wrote ansible playbook to ./ansible/site.yml")
	return nil
}

func RunPlaybook() {
	apco := &options.AnsibleConnectionOptions{
		PrivateKey: viper.GetString("config.ansible.sshKeyPath"),
		User:       viper.GetString("config.ansible.username"),
	}

	apo := &playbook.AnsiblePlaybookOptions{
		Inventory: "ansible/inv.yml",
	}

	// apeo := &options.AnsiblePrivilegeEscalationOptions{
	// 	Become:        true,
	// 	BecomeMethod:  "sudo",
	// 	BecomeUser:    "root",
	// 	AskBecomePass: true,
	// }

	plybk := &playbook.AnsiblePlaybookCmd{
		Playbooks:         []string{"ansible/site.yml"},
		Options:           apo,
		ConnectionOptions: apco,
		Exec: execute.NewDefaultExecute(
			execute.WithEnvVar("ANSIBLE_FORCE_COLOR", "true"),
			execute.WithTransformers(
				results.Prepend("Ansible Playbook Running"),
			),
		),
	}

	err := plybk.Run(context.Background())
	if err != nil {
		panic(err)
	}
}
