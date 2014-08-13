<!--
    This file is part of the AppVulnMS project.


    Copyright (c) 2014 Victor Dorneanu <info AAET dornea DOT nu>

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

    The MIT License (MIT)
-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:output omit-xml-declaration="yes" indent="yes" cdata-section-elements="RawTraffic Raw ResponseTraffic RequestTraffic"/>
    <xsl:strip-space elements="*"/>

    <xsl:template match="/">

        <XmlReport version="0.1">
            <Scanner>
                <Name>Acunetix Web Vulnerability Scanner</Name>
                <Version>9</Version>
            </Scanner>
            <Summary>
                <TotalIssues><xsl:value-of select="count(/ScanGroup/Scan/ReportItems/ReportItem)"/></TotalIssues>
                <ScanDuration><xsl:value-of select="/ScanGroup/Scan/ScanTime"/></ScanDuration>
                <Target>
                    <Host>
                        <xsl:attribute name="name"><xsl:value-of select="/ScanGroup/Scan/StartURL"/></xsl:attribute>
                        <Issues>
                            <xsl:attribute name="total"><xsl:value-of select="count(/ScanGroup/Scan/ReportItems/ReportItem)"/></xsl:attribute>
                            <High>
                                <xsl:value-of select="count(/ScanGroup/Scan/ReportItems/ReportItem/Severity[contains(text(), 'high')])"/>
                            </High>
                            <Medium>
                                <xsl:value-of select="count(/ScanGroup/Scan/ReportItems/ReportItem/Severity[contains(text(), 'medium')])"/>
                            </Medium>
                            <Low>
                                <xsl:value-of select="count(/ScanGroup/Scan/ReportItems/ReportItem/Severity[contains(text(), 'low')])"/>
                            </Low>
                            <Informational>
                                <xsl:value-of select="count(/ScanGroup/Scan/ReportItems/ReportItem/Severity[contains(text(), 'info')])"/>
                            </Informational>
                        </Issues>
                    </Host>
                </Target>
            </Summary>
            <Results>
                <Vulnerabilities>
                    <xsl:for-each select="/ScanGroup/Scan/ReportItems/ReportItem">
                        <Vuln>
                            <xsl:attribute name="type">
                                <xsl:value-of select="Name"/>
                            </xsl:attribute>
                            <xsl:attribute name="error_type"></xsl:attribute>
                            <Description>
                                <xsl:attribute name="html">true</xsl:attribute>
                                <xsl:value-of select="Description"/>
                            </Description>
                            <Comments>
                                <xsl:value-of select="Impact"/>
                            </Comments>
                            <Target>
                                <xsl:attribute name="host"><xsl:value-of select="../../StartURL"/></xsl:attribute>
                            </Target>
                            <Severity>
                                <xsl:value-of select="Severity"/>
                            </Severity>

                            <RawTraffic>
                                <RequestTraffic>
                                    <xsl:value-of select="TechnicalDetails/Request"/>
                                </RequestTraffic>
                                <ResponseTraffic>
                                    <xsl:value-of select="TechnicalDetails/Response"/>
                                </ResponseTraffic>
                            </RawTraffic>

                            <TestProbe>
                                <HTTP>
                                    <Request>
                                        <xsl:attribute name="method"></xsl:attribute>
                                        <URL>
                                            <xsl:value-of select="Affects"/>
                                        </URL>
                                        <Parsed>
                                            <!-- Will be generated by Python -->
                                        </Parsed>
                                        <Payload>
                                            <Input type="parameter">
                                                <xsl:attribute name="name"><xsl:value-of select="Parameter"/></xsl:attribute>
                                                <!-- Will be generated by Python -->
                                            </Input>
                                            <Raw>
                                                <xsl:value-of select="Details"/>
                                            </Raw>
                                        </Payload>
                                    </Request>
                                    <Response>
                                        <Parsed>
                                            <!-- Will be generated by Python -->
                                        </Parsed>
                                    </Response>
                                </HTTP>
                            </TestProbe>

                            <!-- Parse for references -->
                            <References>
                                <xsl:for-each select="References/Reference">
                                    <Ref>
                                        <xsl:attribute name="id"><xsl:value-of select="Database"/></xsl:attribute>
                                        <xsl:attribute name="URL"><xsl:value-of select="URL"/></xsl:attribute>
                                    </Ref>
                                </xsl:for-each>
                            </References>
                        </Vuln>
                    </xsl:for-each>
                </Vulnerabilities>
            </Results>
        </XmlReport>
    </xsl:template>
</xsl:stylesheet>


