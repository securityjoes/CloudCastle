# CloudCastle - Cloud Security Posture Tool

==================================================

**CloudCastle** is a security posture scanner supporting top cloud providers to increase visibility on misconfigurations and threats quickly

![LogoMain](https://raw.githubusercontent.com/securityjoes/CloudCastle/main/images/cloudcastle_logo_main.png)

CloudCastle is super-easy to use, while additionally is very imformative.
Once executed, it will assist you connect to your account, secure your connection with existing vendor-approved tools and scan for risky areas.

![CLIMain](https://raw.githubusercontent.com/securityjoes/CloudCastle/main/images/cloudcastle_CLI-main.png)

CloudCastle isn't meant to be a preventative, countinous monitoring type tool. It's advantage is easy of access and ease of use to allow quick visibility to where you choose.

The command-line interface is easy to use. All you need to do is to choose cloud provider, which will get you into a menu where you start the scan.\
For example, when choosing (1) AWS, CloudCastle will automatically list all your accounts and ask which of them you're interested in scanning.
It will also auto-detect where you don't have access and will remove it from the list.

![CLI2](https://raw.githubusercontent.com/securityjoes/CloudCastle/main/images/cloudcastle_CLI.png)

Once the scan is complete, the scan logs will be saved in the /logs folder in JSON format. You can view the HTML version in the /reports folder, which is easily browsable and includes risk levels for each section of your cloud infrastructure.

![cloudcastle_logs](https://raw.githubusercontent.com/securityjoes/CloudCastle/main/images/cloudcastle_logs.png)

Reports have a unique naming convention, while also including timestamp for convenience of audits.

![report_files](https://raw.githubusercontent.com/securityjoes/CloudCastle/main/images/cloudcastle_report_files.png)

Once you're ready to browse the report, you can access the /reports folder and open the HTML in your browser.
The most interesting part of CloudCastle is its coding modularity. No matter how many accounts you have and how many services are scanned, the report will dynamically allocate space, colours, tables and other elements to ensure data scalability.

![report_browser](https://raw.githubusercontent.com/securityjoes/CloudCastle/main/images/cloudcastle_report.png)

Each pie will assist in understanding the overall risk, the services running and breakdown of each service. Every service will also have risk colours across the report.

==================================================

## 📝 Help us improve! Send your suggestions or reports.

**Submit a request here: [CloudCastle Request](https://github.com/securityjoes/CloudCastle/issues/new)**

**Contact us at: cloudcastle@securityjoes.com**

## 🚨 Need Help with a Security Incident?

### "In a world ruled by AI chaos, only humans can respond"

**Contact us at: response@securityjoes.com**
