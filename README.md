# google-cloud-armor-workshop
Launch a Google Cloud Armor Policy to protect your web apps against known vulnerabilities using Terraform.


## Creating a custom Cloud Armor Policy following the OWASP 10 Best Practices
In this template we'll deploy a custom Cloud Armor Policy using the OWASP 10 rules that Google develop to our use, I take a time to customize some rules and putting in place these rules to make  a well decision to protect our web applications. First, I use a rule to Whitelist known IP addresses, then an admin path rule to protect our admin URL (if we have) and allow the access to only our own public IP, then I follow with a Blacklist rule to put IP addresses of known malicious actors. Later, I use 9 predefined rules of Google about OWASP 10, I decide to separate each of them because with this architecture I can add rules exceptions between them without remove this default rule. As well, I use another rule to block some countries and finally allowing all other internet traffic to my web applications.

This template was created following and using the [Tuning Google Cloud Armor WAF rules](https://cloud.google.com/armor/docs/rule-tuning) and [Creating security policies, rules, and expressions](https://cloud.google.com/armor/docs/configure-security-policies#sample-expressions).


## What file I need modify to use this template
Are only 1 file that you need modify, and this file is the **terraform.tfvars.example**. First you'll need to change the name to **terraform.tfvars** and later modify the next variables:

- [ ] company_name - set the real name of your Company.
- [ ] business_unit - set the name of the business unit or application name that will use this network.
- [ ] project - set your Google Cloud Project ID.
- [ ] admin_path - If your web apps have some administration path, you can put this that path here to protect allowing only to a whitelist to access them.
- [ ] ip_blacklist - If you known some bad IP addresses or IP ranges that are malicious you can put here this information separated by commas.

:warning: :warning: :warning: Remember, I encourage to you don't use an **auth_file** because this can be insecure, instead my recommendation is use the Google Cloud SDK and a default login profile.


## Google Cloud Login Profile
You'll need to install the [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) into your laptop or PC to securily use Terraform and deploy resources without hardcoding an **auth_file**.

Before to initiated using the Terraform, you'll need to configure and set a default profile into your laptop or PC. You can use the next CLI command to do that:

**gcloud auth application-default login**


## Terraform Workspace
This template require that you use a Terraform Workspace, Why? Well, remember that this template is builded to follow the Google Cloud best practices and this best practices tell us that we need identify the "environmment" of our resources.

What are the valid Terraform Workspaces names for this template?

- sbx / for Sandbox Environment
- dev / for Development Environment
- uat / for UAT Environment
- prd / for Production Environment

⭐⭐⭐ And, that's all dudes... you're ready to deploy your Cloud Armor Policy!!! ⭐⭐⭐


## Conclusion
I hope this template is very useful for you, as it's for me. I'd love to hear feedback and suggestions for revisions.

— [Oscar](https://www.linkedin.com/in/oscarmarroquin4/);
