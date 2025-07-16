# CloudCastle - Cloud Security Posture Tool

================================================== 

**CloudCastle** is a security posture scanner supporting top cloud providers to increase visibility on misconfigurations and threats quickly

![image](https://github.com/user-attachments/assets/a8927bf4-b4ca-41e0-9819-d9c4846ae437)


CloudCastle is super-easy to use, while additionally is very imformative.
Once executed, it will assist you connect to your account, secure your connection with existing vendor-approved tools and scan for risky areas.

![image](https://github.com/user-attachments/assets/49005b06-6f62-46b0-a5e0-0aaa75608bda)


CloudCastle isn't meant to be a preventative, countinous monitoring type tool. It's advantage is easy of access and ease of use to allow quick visibility to where you choose.

The command-line interface is easy to use. All you need to do is to choose cloud provider, which will get you into a menu where you start the scan.\
For example, when choosing  (1) AWS, CloudCastle will automatically list all your accounts and ask which of them you're interested in scanning.
It will also auto-detect where you don't have access and will remove it from the list.

![CloudCastle_CLI](https://github.com/user-attachments/assets/3ed8fb91-b162-4b7b-854d-96e1c7527e13)

Once the scan is complete, the scan logs will be saved in the /logs folder in JSON format. You can view the HTML version in the /reports folder, which is easily browsable and includes risk levels for each section of your cloud infrastructure.

![CloudCastle_Logs](https://github.com/user-attachments/assets/5c882f93-8e0f-4c3a-a5e1-8e7893f06768)

Reports have a unique naming convention, while also including timestamp for convenience of audits.

![CloudCastle_Report_Files](https://github.com/user-attachments/assets/1ddce2d2-fdbc-4419-bf00-57e2aeb3ba9e)

Once you're ready to browse the report, you can access the /reports folder and open the HTML in your browser.
The most interesting part of CloudCastle is its coding modularity. No matter how many accounts you have and how many services are scanned, the report will dynamically allocate space, colours, tables and other elements to ensure data scalability.

![cloudcastle_report](https://github.com/user-attachments/assets/f6191dfc-6f21-408b-b4f8-eb300a038ed5)

Each pie will assist in understanding the overall risk, the services running and breakdown of each service. Every service will also have risk colours across the report.

==================================================

## 📝 Help us improve! Send your suggestions or reports.

**Contact us at: cloudcastle@securityjoes.com**

## 🚨 Need Help with a Security Incident?

### "In a world ruled by AI chaos, only humans can respond"

**Contact us at: response@securityjoes.com**
