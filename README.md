The project was developed for prometheus to monitor the cpu and memory metrics of pvdc, vdc in vcloud director.

Before to use the project, please edit config.json file according your vcloud director informations. In this config you must fill in console user and console password in order to collect vcloud appliance (port 5480) metrics.
<code>
{
  "user": "user-name",
  "password": "pass",
  "org": "org-name/system",
  "Href": "vcloud link",
  "Insecure":    true,
  "api_version": "37.1",
  "console_user" : "root",
  "console_pass" : "console pass"
}
</code>

 ./vcd-prometheus-exporter config.json

The metric named vcd_services_status shows the service status of the vcloud director cells. The number represents the service status as follows.
<code>
		0 : "start"
		1 : "running"
		2 : "dead"
		3 : "dead (normal when appliance is in manual failover mode)"
</code>	

Developed by vmware team (sys.dev@trendyol.com)
