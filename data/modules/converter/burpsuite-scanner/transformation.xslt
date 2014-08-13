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
    <xsl:output omit-xml-declaration="no" indent="yes" cdata-section-elements="RawTraffic Raw ResponseTraffic RequestTraffic"/>
    <xsl:strip-space elements="*"/>

    <xsl:template match="/">

        <XmlReport version="0.1">
            <Scanner>
                <Name>Portswigger BurpSuite Pro</Name>
                <Version><xsl:value-of select="/issues/@burpVersion"/></Version>
            </Scanner>
            <Summary>
                <TotalIssues><xsl:value-of select="count(/issues/issue)"/></TotalIssues>
                <ScanDuration>No scan duration available</ScanDuration>
                <Target>
                    <Host>
                        <xsl:attribute name="name"><xsl:value-of select="/issues/issue/host"/></xsl:attribute>
                        <Issues>
                            <xsl:attribute name="total"><xsl:value-of select="count(/issues/issue)"/></xsl:attribute>
                            <High>
                                <xsl:value-of select="count(/issues//issue/severity[contains(text(), 'High')])"/>
                            </High>
                            <Medium>
                                <xsl:value-of select="count(/issues//issue/severity[contains(text(), 'Medium')])"/>
                            </Medium>
                            <Low>
                                <xsl:value-of select="count(/issues//issue/severity[contains(text(), 'Low')])"/>
                            </Low>
                            <Informational>
                                <xsl:value-of select="count(/issues//issue/severity[contains(text(), 'Information')])"/>
                            </Informational>
                        </Issues>
                    </Host>
                </Target>
            </Summary>
            <Results>
                <Vulnerabilities>
                    <xsl:for-each select="/issues/issue">
                        <Vuln>
                            <xsl:attribute name="type">
                                <xsl:value-of select="name"/>
                            </xsl:attribute>
                            <xsl:attribute name="error_type"></xsl:attribute>
                            <Description>
                                <xsl:value-of select="issueDetail"/>
                            </Description>
                            <Comments>
                                <xsl:value-of select="issueBackground"/>
                            </Comments>
                            <Target>
                                <xsl:attribute name="host"><xsl:value-of select="host"/></xsl:attribute>
                            </Target>
                            <Severity>
                                <xsl:value-of select="severity"/>
                            </Severity>

                            <RawTraffic>
                                <MergedTraffic base64="false"/>
                                <RequestTraffic>
                                    <xsl:attribute name="base64">true</xsl:attribute>
                                    <xsl:value-of select="requestresponse/request"/>
                                </RequestTraffic>
                                <ResponseTraffic>
                                    <xsl:attribute name="base64">true</xsl:attribute>
                                    <xsl:value-of select="requestresponse/response"/>
                                </ResponseTraffic>
                            </RawTraffic>

                            <TestProbe>
                                <HTTP>
                                    <Request>
                                        <xsl:attribute name="method"></xsl:attribute>
                                        <URL>
                                            <xsl:value-of select="path"/>
                                        </URL>
                                        <Parsed>
                                            <!-- Will be generated by Python -->
                                        </Parsed>
                                        <Payload>
                                            <Input>
                                                <!-- Will be generated by Python -->
                                            </Input>
                                            <Raw>
                                                <xsl:value-of select="location"/>
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
                        </Vuln>
                    </xsl:for-each>
                </Vulnerabilities>
            </Results>
        </XmlReport>
    </xsl:template>
</xsl:stylesheet>


