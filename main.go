package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Cfg struct {
	User         string
	Password     string
	Org          string
	Href         string
	Insecure     bool
	Api_version  string
	Console_user string
	Console_pass string
	token        string
}
type Cells struct {
	ResultTotal  int           `json:"resultTotal"`
	PageCount    int           `json:"pageCount"`
	Page         int           `json:"page"`
	PageSize     int           `json:"pageSize"`
	Associations []interface{} `json:"associations"`
	Values       []struct {
		ID               string    `json:"id"`
		ProductBuildDate time.Time `json:"productBuildDate"`
		IsActive         bool      `json:"isActive"`
		Name             string    `json:"name"`
		PrimaryIP        string    `json:"primaryIP"`
		ProductVersion   string    `json:"productVersion"`
	} `json:"values"`
}
type Backup struct {
	ListOfBackupFiles []listOfBackupFiles `json:"listOfBackupFiles"`
	PageCount         int                 `json:"pageCount"`
	PageSize          int                 `json:"pageSize"`
	ResultTotal       int                 `json:"resultTotal"`
}
type listOfBackupFiles struct {
	Date     time.Time `json:"date"`
	Location string    `json:"location"`
	Name     string    `json:"name"`
	Size     int       `json:"size"`
	Version  string    `json:"version"`
}
type Services []struct {
	ServiceName string `json:"serviceName"`
	Status      string `json:"status"`
}

type cellServices []struct {
	CellName    string `json:"cellName"`
	ServiceName string `json:"serviceName"`
	Status      string `json:"status"`
}

func newHTTPClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}

func (config *Cfg) getCells(client *http.Client) (*Cells, error) {
	var cells Cells
	config.Href = fmt.Sprintf("https://%s/cloudapi/1.0.0/cells", link)
	b, err := config.getURL(client, "")
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	err = json.Unmarshal([]byte(b), &cells)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	//fmt.Println("90:cells : ", cells)
	return &cells, err
}
func (cells *Cells) getCellServices(config *Cfg, client *http.Client) (cellServices, error) {
	var services Services
	var cellServicesResult cellServices
	var consoleLink string
	auth := base64.StdEncoding.EncodeToString([]byte(config.Console_user + ":" + config.Console_pass))
	/*
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
	*/
	i := 0

	for _, cell := range cells.Values {
		consoleLink = fmt.Sprintf("https://%s:5480/api/1.0.0/services", cell.Name)
		req, err := http.NewRequest("GET", consoleLink, nil)
		req.Header.Add("Accept", "application/*;version="+config.Api_version)
		req.Header.Add("Authorization", "Basic "+auth)
		res, err := client.Do(req)
		if err != nil {
			fmt.Println(err, req)
		}
		defer res.Body.Close()
		if err != nil {
			fmt.Println("Error sending HTTP request:", err)
			os.Exit(22)
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
		err = json.Unmarshal([]byte(body), &services)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		for _, service := range services {
			cellService := struct {
				CellName    string `json:"cellName"`
				ServiceName string `json:"serviceName"`
				Status      string `json:"status"`
			}{
				CellName:    cell.Name,
				ServiceName: service.ServiceName,
				Status:      service.Status,
			}
			cellServicesResult = append(cellServicesResult, cellService)

		}
		i++
	}
	return cellServicesResult, nil
}

func (cells *Cells) getBackupStatus(config *Cfg, client *http.Client) ([]listOfBackupFiles, error) {
	var backup Backup
	var listOfBFs []listOfBackupFiles
	var backupCheckCell string

	// if the cell state is active, the backup status list query sending  to active cell
	for i := 0; i < len(cells.Values); i++ {
		if cells.Values[i].IsActive {
			backupCheckCell = cells.Values[i].Name
			break
		}

	}
	auth := base64.StdEncoding.EncodeToString([]byte(config.Console_user + ":" + config.Console_pass))
	/*
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
	*/
	pagecount := 1
	for {
		consoleLink := fmt.Sprintf("https://%s:5480/api/1.0.0/backups?page=%d", backupCheckCell, pagecount)
		req, err := http.NewRequest("GET", consoleLink, nil)
		if err != nil {
			fmt.Println(err, req)
		}
		req.Header.Add("Accept", "application/*;version="+config.Api_version)
		req.Header.Add("Authorization", "Basic "+auth)
		res, err := client.Do(req)
		if err != nil {
			fmt.Println("Error sending HTTP request:", err)
			os.Exit(11)
		}

		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
		err = json.Unmarshal([]byte(body), &backup)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		pagecount++

		listOfBFs = append(listOfBFs, backup.ListOfBackupFiles...)
		//fmt.Println(listOfBFs)
		if pagecount > backup.PageCount {
			break
		}
	}

	return listOfBFs, nil
}
func LoadConfig(path string) (*Cfg, error) {
	var config Cfg

	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(content, &config)
	if err != nil {
		return nil, err
	}
	//println("Load config : ", config.Console_user)
	return &config, nil
}
func (info *Cfg) getToken(client *http.Client) { //string {
	var operation string
	if info.Api_version >= "33" {
		if strings.ToLower(info.Org) == "system" {
			operation = "cloudapi/1.0.0/sessions/provider"
		} else {
			operation = "cloudapi/1.0.0/sessions"
		}
	} else {
		operation = "api/sessions"
	}
	//fmt.Println(info)
	auth := base64.StdEncoding.EncodeToString([]byte(info.User + "@" + info.Org + ":" + info.Password))
	/*
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
	*/
	req, err := http.NewRequest("POST", "https://"+info.Href+"/"+operation, nil)
	if err != nil {
		fmt.Println(err, req)
	}
	req.Header.Add("Accept", "application/*;version="+info.Api_version)
	req.Header.Add("Authorization", "Basic "+auth)
	//fmt.Println(req)
	res, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		os.Exit(1)
	}
	defer res.Body.Close()

	//fmt.Print(info.Href, "\n", res.Header, "\n")
	token := ""
	for head, v := range res.Header {
		//println(head)
		if head == "X-Vmware-Vcloud-Access-Token" {
			token = v[0]
			//fmt.Println(v[0])
		}

	}
	info.token = token
	//fmt.Println(token)
}

func (cfg *Cfg) getURL(client *http.Client, header string) ([]byte, error) {
	//fmt.Println("client:", client.Transport)
	//var respData []map[string]interface{}
	/*
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}*/
	req, err := http.NewRequest("GET", cfg.Href, nil)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	if header == "" {
		req.Header.Add("Accept", "application/json;version="+cfg.Api_version)
	} else {
		req.Header.Add("Accept", "application/"+header+"+json;version="+cfg.Api_version)

	}
	req.Header.Add("Authorization", "Bearer "+cfg.token)
	//println(req.Header.Get("Accept"))
	//println(cfg.Href)
	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	//	fmt.Println("301: body : ", body)
	return body, nil
}

// clean "urn:vcloud:org:" string from org ID
func returnID(urn string) string {
	urn = strings.Replace(urn, "urn:vcloud:providervdc:", "", -1)
	return strings.Replace(urn, "urn:vcloud:org:", "", -1)
}
func parseHostname(Href string) string {
	url, err := url.Parse(Href)
	if err != nil {
		log.Fatal(err)
	}
	return strings.TrimPrefix(url.Hostname(), "www.")
}

var (
	link   string
	client *http.Client
	//token          string
	pvdcMemoryUsed = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pvdc_memory_used",
			Help: "Used memory of PvDC (MB)",
		}, []string{"link", "pvdc"})
	pvdcMemoryTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pvdc_memory_total",
			Help: "Total memory of the PvDC (MB)",
		}, []string{"link", "pvdc"})
	pvdcCpuUsed = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pvdc_cpu_used",
			Help: "Used CPU of the PvDC (MHz)",
		}, []string{"link", "pvdc"})
	pvdcCpuTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pvdc_cpu_total",
			Help: "Total CPU of the PvDC (MHz)",
		}, []string{"site", "pvdc"})
	orgMemoryUsed = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vdc_memory_used",
			Help: "Memory usage of the vDC (MB)",
		}, []string{"site", "org"})
	orgCpuUsed = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vdc_cpu_used",
			Help: "CPU usage of the vDC (Mhz)",
		}, []string{"site", "org"})
	orgPoweredonVms = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vdc_poweredon_vms",
			Help: "Number of powered on vms in vDC",
		}, []string{"site", "org"})
	vcdBackupStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vcd_backup_status",
			Help: "vCloud Directors backup status",
		}, []string{"site"})
	vcdBackupSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vcd_backup_size",
			Help: "vCloud Directors Cell backup size",
		}, []string{"site", "name", "date"})
	vcdServicesStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vcd_services_status",
			Help: "vCloud Directors Cell appliance services status",
		}, []string{"cell", "name"})
)

func main() {
	type pvdc struct {
		ID                    string `json:"id"`
		Name                  string `json:"name"`
		Description           string `json:"description"`
		IsEnabled             bool   `json:"isEnabled"`
		MaxSupportedHwVersion string `json:"maxSupportedHwVersion"`
		CreationStatus        string `json:"creationStatus"`
		NsxTManager           string `json:"nsxTManager"`
		VimServer             struct {
			name string
			id   string
		} `json:"vimServer"`
	}

	type pvdclists struct {
		ResultTotal  int         `json:"resultTotal"`
		PageCount    int         `json:"pageCount"`
		Page         int         `json:"page"`
		PageSize     int         `json:"pageSize"`
		Associations interface{} `json:"associations"`
		Values       []pvdc      `json:"values"`
	}
	type pvdcMetrics struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Description     string `json:"description"`
		ComputeCapacity struct {
			Cpu struct {
				CpuUsed  float32 `json:"used"`
				CpuTotal float32 `json:"total"`
			} `json:"cpu"`
			Memory struct {
				MemoryUsed  float32 `json:"used"`
				MemoryTotal float32 `json:"total"`
			} `json:"memory"`
		}
	}
	type org struct {
		ID             string `json:"id"`
		Name           string `json:"name"`
		DisplayName    string `json:"displayName"`
		Description    string `json:"description"`
		IsEnabled      bool   `json:"isEnabled"`
		OrgVdcCount    int    `json:"orgVdcCount"`
		CatalogCount   int    `json:"catalogCount"`
		VappCount      int    `json:"vappCount"`
		RunningVMCount int    `json:"runningVMCount"`
		UserCount      int    `json:"userCount"`
		DiskCount      int    `json:"diskCount"`
		CanPublish     bool   `json:"canPublish"`
	}

	type orgList struct {
		ResultTotal  int         `json:"resultTotal"`
		PageCount    int         `json:"pageCount"`
		Page         int         `json:"page"`
		PageSize     int         `json:"pageSize"`
		Associations interface{} `json:"associations"`
		Values       []org       `json:"values"`
	}
	type vdcMetrics struct {
		SiteReference []struct {
			Name string `json:"name"`
		} `json:"siteReference"`
		OrgReference []struct {
			Name string `json:"name"`
		} `json:"orgReference"`
		OrgVdcReference []struct {
			Name string `json:"name"`
		} `json:"orgVdcReference"`
		NumberOfPoweredOnVms int `json:"numberOfPoweredOnVms"`
		FlexVdcSummary       struct {
			OtherAttributes      interface{}   `json:"otherAttributes"`
			MemoryConsumptionMB  float64       `json:"memoryConsumptionMB"`
			MemoryReservationMB  float64       `json:"memoryReservationMB"`
			CpuConsumptionMhz    float64       `json:"cpuConsumptionMhz"`
			CpuReservationMhz    float64       `json:"cpuReservationMhz"`
			StorageConsumptionMB float64       `json:"storageConsumptionMB"`
			VCloudExtension      []interface{} `json:"vCloudExtension"`
		} `json:"flexVdcSummary"`
	}

	var pvdcmetric pvdcMetrics
	var body vdcMetrics
	var orglist orgList
	var org2 []org
	var pvdclist pvdclists
	var pvdc2 []pvdc
	prometheus.MustRegister(pvdcMemoryUsed)
	prometheus.MustRegister(pvdcMemoryTotal)
	prometheus.MustRegister(pvdcCpuUsed)
	prometheus.MustRegister(pvdcCpuTotal)

	prometheus.MustRegister(orgMemoryUsed)
	prometheus.MustRegister(orgCpuUsed)
	prometheus.MustRegister(orgPoweredonVms)
	prometheus.MustRegister(vcdBackupSize)
	prometheus.MustRegister(vcdBackupStatus)
	prometheus.MustRegister(vcdServicesStatus)
	sumMemConsumption := float64(0)
	sumCpuConsumption := float64(0)
	sumPoweredOnVMs := 0
	client = newHTTPClient()
	cfg, err := LoadConfig("config.json")
	if err != nil {
		panic(err)
	}
	link = cfg.Href
	cfg.getToken(client)

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {

		pagecount := 1
		for {

			cfg.Href = fmt.Sprintf("https://%s/cloudapi/1.0.0/providerVdcs?page=%d", link, pagecount)
			b, err := cfg.getURL(client, "")
			if err != nil {
				fmt.Println(err)
				panic(err)
			}
			err = json.Unmarshal([]byte(b), &pvdclist)
			if err != nil {
				fmt.Println(err)
				panic(err)
			}
			pagecount++

			pvdc2 = append(pvdc2, pvdclist.Values...)
			//println(page)

			if pagecount > pvdclist.PageCount {
				break
			}
			//println(string([]byte(b)))
		}

		for _, pvdcs := range pvdc2 {
			//fmt.Println("ID: ", returnID(orgs.ID), "Name: ", orgs.Name, "isEnabled: ", orgs.IsEnabled, "OrgVdcCount: ", orgs.OrgVdcCount, "RunningVMCount: ", orgs.RunningVMCount)
			cfg.Href = "https://" + link + "/api/admin/providervdc/" + returnID(pvdcs.ID)
			b, err := cfg.getURL(client, "vnd.vmware.admin.providervdc")
			if err != nil {
				fmt.Println(err)
				panic(err)
			}
			//println(string(b))
			err = json.Unmarshal([]byte(b), &pvdcmetric)
			if err != nil {
				fmt.Println(err)
				panic(err)
			}
			//fmt.Println("Name : ", pvdcmetric.Name, "Description :", pvdcmetric.Description, "\n", "Memory Used: ", pvdcmetric.ComputeCapacity.Memory.MemoryUsed/1024, "Memory Total: ", pvdcmetric.ComputeCapacity.Memory.MemoryTotal/1024, "Usage% :", pvdcmetric.ComputeCapacity.Memory.MemoryUsed/pvdcmetric.ComputeCapacity.Memory.MemoryTotal*100, " CPU Used :", pvdcmetric.ComputeCapacity.Cpu.CpuUsed/1000, " CPU Total :", pvdcmetric.ComputeCapacity.Cpu.CpuTotal/1000, "Usage% :", pvdcmetric.ComputeCapacity.Cpu.CpuUsed/pvdcmetric.ComputeCapacity.Cpu.CpuTotal*100)
			pvdcMemoryUsed.WithLabelValues(parseHostname(cfg.Href), pvdcmetric.Name).Set(float64(pvdcmetric.ComputeCapacity.Memory.MemoryUsed))
			pvdcMemoryTotal.WithLabelValues(parseHostname(cfg.Href), pvdcmetric.Name).Set(float64(pvdcmetric.ComputeCapacity.Memory.MemoryTotal))
			pvdcCpuUsed.WithLabelValues(parseHostname(cfg.Href), pvdcmetric.Name).Set(float64(pvdcmetric.ComputeCapacity.Cpu.CpuUsed))
			pvdcCpuTotal.WithLabelValues(parseHostname(cfg.Href), pvdcmetric.Name).Set(float64(pvdcmetric.ComputeCapacity.Cpu.CpuTotal))

		}
		// collect Org vdc metrics

		pagecount = 1
		for {

			cfg.Href = fmt.Sprintf("https://%s/cloudapi/1.0.0/orgs?page=%d", link, pagecount)
			b, err := cfg.getURL(client, "")
			if err != nil {
				fmt.Println(err)
				panic(err)
			}
			err = json.Unmarshal([]byte(b), &orglist)
			if err != nil {
				fmt.Println(err)
				panic(err)
			}
			pagecount++

			org2 = append(org2, orglist.Values...)
			//println(page)

			if pagecount > orglist.PageCount {
				break
			}
			//println(string([]byte(b)))
		}

		sumMemConsumption = float64(0)
		sumCpuConsumption = float64(0)
		sumPoweredOnVMs = 0
		for _, orgs := range org2 {
			//fmt.Println("ID: ", returnID(orgs.ID), "Name: ", orgs.Name, "isEnabled: ", orgs.IsEnabled, "OrgVdcCount: ", orgs.OrgVdcCount, "RunningVMCount: ", orgs.RunningVMCount)
			cfg.Href = "https://" + link + "/api/org/" + returnID(orgs.ID) + "/vdcRollup"
			b, err := cfg.getURL(client, "vnd.vmware.vcloud.orgvdcRollup")
			if err != nil {
				fmt.Println(err)
				panic(err)
			}
			//println(string(b))
			err = json.Unmarshal([]byte(b), &body)
			if err != nil {
				fmt.Println(err)
				panic(err)
			}

			//fmt.Println("lenght of vdc : ", len(body.OrgVdcReference))
			//fmt.Println("Site Name:", body.SiteReference[0].Name, " org: ", body.OrgReference[0].Name, "FlexVdcSummary:MemoryConsumptionGB : ", body.FlexVdcSummary.MemoryConsumptionMB/1024, " CPU consumption GHz: ", body.FlexVdcSummary.CpuConsumptionMhz/1000, " NumberOfPoweredOnVms : ", body.NumberOfPoweredOnVms)
			sumMemConsumption += body.FlexVdcSummary.MemoryConsumptionMB / 1024
			sumCpuConsumption += body.FlexVdcSummary.CpuConsumptionMhz / 1000
			sumPoweredOnVMs += body.NumberOfPoweredOnVms

			orgMemoryUsed.WithLabelValues(body.SiteReference[0].Name, body.OrgReference[0].Name).Set(float64(body.FlexVdcSummary.MemoryConsumptionMB))
			orgCpuUsed.WithLabelValues(body.SiteReference[0].Name, body.OrgReference[0].Name).Set(float64(body.FlexVdcSummary.CpuConsumptionMhz))
			orgPoweredonVms.WithLabelValues(body.SiteReference[0].Name, body.OrgReference[0].Name).Set(float64(body.NumberOfPoweredOnVms))

		}

		cells, err := cfg.getCells(client)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		//fmt.Println("594:cells:", cells)
		backups, err := cells.getBackupStatus(cfg, client)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		//err = json.Unmarshal(t, &lOBF)
		now := time.Now()
		today := now.Day()
		layout := "2006-01-02 15:04:05 -0700 MST"
		backupStatus := 0
		stat := 0
		for _, bck := range backups {
			//fmt.Println("backups : ", bck.Name, "size : ", bck.Size, "Date : ", bck.Date, "backup Status : ", backupStatus)

			t, err := time.Parse(layout, bck.Date.String())
			if err != nil {
				panic(err)
			}
			if t.Day() == today {
				backupStatus = 1
			}
			vcdBackupSize.WithLabelValues(body.SiteReference[0].Name, bck.Name, bck.Date.String()).Set(float64(bck.Size))

			//fmt.Println("backups : ", bck.Name, "size : ", bck.Size, "Date : ", bck.Date)
		}
		//fmt.Println("backup Status : ", backupStatus)
		vcdBackupStatus.WithLabelValues(body.SiteReference[0].Name).Set(float64(backupStatus))

		services, err := cells.getCellServices(cfg, client)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		for _, service := range services {
			switch service.Status {
			case "start":
				stat = 0
			case "running":
				stat = 1
			case "dead":
				stat = 2
			case "dead (normal when appliance is in manual failover mode)":
				stat = 3
			}
			//fmt.Println("cell : ", service.CellName, "service : ", service.ServiceName, "status : ", stat)
			vcdServicesStatus.WithLabelValues(service.CellName, service.ServiceName).Set(float64(stat))
		}
		promhttp.Handler().ServeHTTP(w, r)
	}) //http.HandleFunc
	// start prometheus metric page
	fmt.Println("0.0.0.0:9273/metrics is started")
	//http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":9273", nil)

}
