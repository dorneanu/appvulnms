# Introduction

-------

This bundle of python scripts is aimed at everyone in the IT security industry who has to inspect, manage and track application vulnerabilities and create nice looking reports. At the moment there is de facto no standard format/layout to describe application vulnerabilities. In the past history there were several suggestions but none of them was established as a standard.

Besides that every (web) application scanner uses its own reporting format so you can't really compare results from different vendors.  This is here the idea for this whole project came of: The ability to compare different scanning results for better vulnerability scan coverage.

# Technology

----

I mainly use Python to to the most important jobs because of its simplicity and OS independence. Among Python 3.x I make heavy use of:

* **XML**
  Used to store vulnerability data and to convert scanning results into preferred layout

* **XSLT**
  XML transformation at its best. Basically there is one XSLT file for every single application scanner to do the transformation part. The rest is performed by Python magic.

* **SQLite**
  I love SQL and I definitely love SQLite for being a lite, useful RDMS. I generally like the idea of putting data into relations and therefor create astonishing results. Just try to do the same with Excel and afterwards you'll love *relational* data bases.


# The AppVuln* suite

----

The vulnerability management system (VMS) consists of 3 main components

* **AppVulnXML**
   Specifies how to store application vulnerability data and structures it a useful parseable way. In case of HTTP the traffic is being      parsed and saved in smaller structures like: URL, headers, POST parameters, data etc.

* **AppVulnDB**
   In order to track all the vulnerabilities found within your favorite scanning tool, you'll need a DB to take of the management itself. AppVulnDB is basically the vulnerability management system mentioned before and records vulnerabilities (and metadata) in the AppVulnXML format. So this component will provide you with an API to import/export AppVulnXML files.

* **AppVulnMS**
  If you put all together, you'll get a VMS able to convert scanning results into AppVulnXML format and finally import them to the AppVulnDB. At the moment the AppVulnMS describes the whole software bundle you'll get.


## AppVulnXML

The XML describes a way how to handle and store application vulnerability data. Meta data is stored as well. Generally speaking you'll have 3 main section within any XML document:

* **Scanner information**
  Includes details about the scanner itself like name, version etc.

* **Summary**
  You'll get a brief short summary about results: How many findings? How many High/Medium/Log/Informational issues? Scan duration ...

* **Results**
  Last but not least you'll get the results section which contains all vulnerability related data.


### Scanner information

~~~~~
<Scanner>
        <Name>Favourite scanning tool</Name>
        <Version>x.y.z</Version>
</Scanner>
~~~~~

### Summary

~~~~~

<Summary>
    <TotalIssues>41</TotalIssues>
    <ScanDuration/>
    <Targets>
      <Host name="http://exmple.com">
        <Issues total="41">
          <High>7</High>
          <Medium>0</Medium>
          <Low>1</Low>
          <Informational>33</Informational>
        </Issues>
      </Host>
    </Targets>
  </Summary>

~~~~~

### Results

~~~~~

 <Results>
    <Vulnerabilities>
      <Vuln type="authBypassSQLInjection" error_type="">
        <Description>Authentication Bypass Using SQL Injection</Description>
        <Comments>SQL Injection</Comments>
        <Target host="http://demo.testfire.net/bank/login.aspx"/>
        <Severity>High</Severity>
        <RawTraffic>
          <RequestTraffic base64="false"><![CDATA[...]]></RequestTraffic>
          <ResponseTraffic base64="false"><![CDATA[...]]></ResponseTraffic>
        </RawTraffic>
        <TestProbe>
          <HTTP>
            <Request method="POST" version="HTTP/1.1">
              <URL>/bank/login.aspx</URL>
              <Parsed>
                <Header name="Content-Length" value="41"/>
                ...
                <Header name="Cookie" value="ASP.NET_SessionId=zocks0555ove35rprhyz0w45"/>
                <Header name="Cookie" value="amSessionId=65819338695"/>
                <Header name="Cookie" value="amUserInfo=UserName=anNtaXRo&amp;Password=ZGVtbzEyMzQ="/>
                <Data><![CDATA[uid=jsmith&passw=demo1234&btnSubmit=Login]]></Data>
              </Parsed>
              <Payload>
                <Input type="Parameter" name="passw"><![CDATA[4ppSc4n]]></Input>
                <Raw><![CDATA[...]]></Raw>
              </Payload>
            </Request>
            <Response version="HTTP/1.0" status="302" reason="Moved Temporarily">
              <Parsed>
                <Header name="Date" value="Mon, 01 Jul 2013 12:17:44 GMT"/>
                <Header name="Expires" value="-1"/>
                <Header name="Content-Type" value="text/html; charset=utf-8"/>
                <Header name="Content-Length" value="136"/>
                <Header name="Proxy-Connection" value="keep-alive"/>
                <Header name="X-Powered-By" value="ASP.NET"/>
                ....
                <Data base64="False"><![CDATA[...]]></Data>
              </Parsed>
            </Response>
          </HTTP>
        </TestProbe>
        <References>
          <Ref type="CWE" id="CWE-566" URL="http://cwe.mitre.org/data/definitions/566.html"/>
          <Ref id="external-site" type="&quot;Web Application Disassembly with ODBC Error Messages&quot; (By David Litchfield)" URL="http://www.cgisecurity.com/lib/webappdis.doc"/>
          <Ref id="external-site" type="SQL Injection Training Module" URL="http://download.boulder.ibm.com/ibmdl/pub/software/dw/richmedia/rational/08/appscan_demos/sqlinjection/viewer.swf#recorded_advisory"/>
        </References>
      </Vuln>

      ....
   </Vulnerabilities>
</Results>

~~~~~

## AppVulnDB

At the moment the vulnerability DB consists of following tables:

* **scanner**
  Contains scanner related details, e.g. version

* **scan**
  A scan entry contains all summary information about a single scan:

    * *scope* (e.g. Single scan)

    * *target* (e.g. http://example.com)

    * *start/finish date of scan*

    * *scanner ID* (references one entry in the *scanner* table)

    * *number of total vulnerabilities*

    * etc.

* **vulnerability**
   The main table aimed to store all valuable information about a vulnerability:

   * *type* (e.g. XSS, CSRF, Buffer Overflow etc.)

   * *name* (e.g. "XSS in URL bla bla")

   * *description*

   * *error_type* (e.g. "false_positive" or simply empty suggesting that the vulnerability is a real one)

   * *severity* (e.g. High, Medium, Low, Informational)

   * *scanner ID* (reference to *scanner* table)

   * *poc_type_id* (reference to the *poc_type* table)

   * *poc_id*

   * *date added*

   * *comments*

* **poc_type**
  Since one application can communicate through different protocols, different PoC (Proof of Concept) types are needed. Example: If you want to describe a XSS vulnerability you'll need a different level of granularity as a buffer overflow vulnerability. That's why I think different PoC types are needed depending on the protocols the application is able to use. Since the focus of AppVulnMS is more or less on *web* application vulnerabilities, there'll be a default PoC type called *http*. But feel free to add your own types.

* **poc_type_http**
  Handles PoC data for the PoC type *http*:

  * *URL*

  * *method* (e.g. GET, POST, DELETE, HEAD etc.)

  * *request headers*
     This field contains all request headers as a parseable XML structure.

  * *request cookies*
     This field contains all request cookies as a parseable XML structure.

  * *request_data*
     If you have a POST method, then you'll always want to store the POST data as well.

  * *response headers*

  * *response cookies*

  * *response data*
     This field contains the response data from server in plain text.

  * *input type*
     Describes what kind of input type was used to trigger the payload: Cookie, parameter, request header etc.

  * *input name*
     Name of the cookie, parameter, request header etc.

  * *input data*
     Contains payload input data sent to the application.

  * *scanner* (reference to the *scanner* table)

* **reference**
  Contains tool specific references related to one vulnerability.

  * *reference type* (e.g. external site, CVE, CWE. NVD etc.)

  * *name of the reference* (e.g. "Read more about SQLi ... ")

  * *reference ID*
   This is very handy when it comes to public vulnerabilities data bases like CVE, CWE etc. In that case the  reference ID contains the CVE/CWE/[...] ID you can lookup in that particular data base.

  * *URL*


Having those vulnerability details one could easily generate fancy pie charts or diagrams using external libraries like [HighCharts](http://www.highcharts.com/) or [D3](http://d3js.org/). No integration with all this kind of libraries is planed.


## AppVulnMS

The management system itself tries to act as a connecting glue between the scan results, the AppVulnXML files and the AppVulnDB. You could think of some modular framework - although it's not - easy to extend with your new modules. I tried to simplify the basic structure of a single module and give the user the ability to run every module from the command line. Every module should at least have some *--help* option:

~~~~~

$ python3 bin/AppVulnMS-cli.py m <here comes the module name> --help

....

~~~~

Each module should have a *parent category* like *convert*, *appvulndb*, *report* and so on: Just have a look inside the *modules* directory.

### Available modules

Currently there are following categories and modules available:

* **converter**

  * IBM Rational AppScan 8.x

  * Acunetix 9.x

  * PortSwigger Burp Suite


* **AppVulnDB**

  * SQLite: SQLite implementation of AppVulnDB


# Usage
----

Feel free to clone this repository. In order to get this work make sure you have following packages installed:

* **python 3.x**

* **python-sqlite**

* **python-lxml**
  Python3 binding for the libxml2 and libxslt libraries


## Basic

The basic run would be:

~~~~~

$ python3 bin/AppVulnMS-cli.py -h

       _           __   __    _      __  __ ___
      /_\  _ __ _ _\ \ / /  _| |_ _ |  \/  / __|
     / _ \| '_ \ '_ \ V / || | | ' \| |\/| \__ \
    /_/ \_\ .__/ .__/\_/ \_,_|_|_||_|_|  |_|___/
          |_|  |_|

    --------------------------------------------
    Application Vulnerability Management System


usage: AppVulnMS-cli.py [-h] {m} ...

positional arguments:
  {m}         Choose mode
    m         Interact with available modules

optional arguments:
  -h, --help  show this help message and exit

~~~~~

As you can at the moment there is only one mode to run *AppVulnMS* with. In the near future an additional mode "db" should be added which is supposed to handle all the DB actions. Right now the DB activities are bundled into one single module.

Now let's have a look at the additional parameters for the (m)odule mode:

~~~~~

$ python3 bin/AppVulnMS-cli.py m -h

...

usage: AppVulnMS-cli.py m [optional args] [positional args]

------------------------------------------------------------------------
In order to list available modules:
    $ AppVulnMS-cli.py m -l

To interact with specific module:
    $ AppVulnMS-cli.py m <modules name> <modules parameters>

To get modules parameters:
    $ AppVulnMS-cli.py m <modules name> --help
------------------------------------------------------------------------

::: Interact with the available modules.

positional arguments:
  module_name         Modules name
  module_params       Modules parameters

optional arguments:
  -h, --help          show this help message and exit
  -q, --quiet         Keep it quiet
  -v, --verbose       Add verbosity
  -l, --list-modules  List available modules

~~~~~


Let's have a look at the available modules:


~~~~~

$ python3 bin/AppVulnMS-cli.py m -l

...

[INFO]  Available modules:
::: vms/appvulndb/sqlite
    _ Desc       Manages application vulnerabilities in SQLite DB
    _ Author     Cyneox / nullsecurity.net
    _ Version    v0.1
    _ URL:       http://sqlite.org/

::: converter/xml/acunetix
    _ Desc       Converts Acunetix into WAVXML format
    _ Author     Cyneox / nullsecurity.net
    _ Version    v0.1
    _ URL:       http://www.acunetix.com

::: converter/xml/burpsuite-scanner
    _ Desc       Converts BurpSuite scanner results into WAVXML
    _ Author     Cyneox / nullsecurity.net
    _ Version    v0.1
    _ URL:       http://portswigger.net/burp/

::: converter/xml/ibm-appscan
    _ Desc       Converts IBM AppScan results into suitable XML using XSLT
    _ Author     Cyneox / nullsecurity.net
    _ Version    v0.1
    _ URL:       http://www-03.ibm.com/software/products/us/en/appscan/

~~~~~

## Convert scanning results

In order to convert scanning results you'll have to export them first and then run AppVulnMS. For Acunetix scanning results that'd be:

~~~~~

$ python3 bin/AppVulnMS-cli.py m converter/xml/acunetix -i Acunetix-Export.xml -x data/modules/converter/acunetix/transformation.xslt -o Acunetix-Export-Converted.xml

~~~~


Explanations:

* -i Acunetix-Export.xml
   Specified the input file.

* -x data/modules/[...]/transformation.xslt
   Specifies the XSLT file to use for the transformation. You could of course use your own one.

* -o Acunetix-Export-Converted.xml
   Where to store output.


## Import files to DB

Let's have a look at the implemented module and its options:


~~~~~
$ python3 bin/AppVulnMS-cli.py m vms/appvulndb/sqlite --help

...

usage: AppVulnMS-cli.py [-h] {init,import} ...

positional arguments:
  {init,import}  Choose mode
    init         Create SQLite AppVulnDB
    import       Import vulns in AppVulnXML format into DB

optional arguments:
  -h, --help     show this help message and exit
~~~~~

So first of all we'll have to init/create a DB file:


~~~~~

$  python3 bin/AppVulnMS-cli.py m vms/appvulndb/sqlite init -f appvulndb.sqlite

...

[INFO]  Succesfully created DB

~~~~~


And now we could easily import the previous generated AppVulnXML file into the DB:


~~~~~

$ python3 bin/AppVulnMS-cli.py m vms/appvulndb/sqlite import -d appvulndb.sqlite -f tmp/acunetix.xml

...

[INFO]  Successfully imported data into DB

~~~~~


Now you can verify the results using some SQLite client:


~~~~~

$ echo "SELECT COUNT(*) FROM vulnerability;SELECT * FROM scanner;" | sqlite3 -interactive appvulndb.sqlite
SQLite version 3.8.2 2013-12-06 23:53:30
Enter ".help" for instructions
Enter SQL statements terminated with a ";"
sqlite> SELECT COUNT(*) FROM vulnerability;SELECT * FROM scanner;
179
1|Acunetix Web Vulnerability Scanner|9|
sqlite>

~~~~~


# Disclaimer

This piece of software works as it is. Although its far behind from being only  proof of concept, you could still use it in your company. Since I've code it in my free time any credits, "I LIKE"s whatever would be appreciated. If you have any suggestions about new modules, better core design or simply want to say "Hello", don't hesitate to contact me.
