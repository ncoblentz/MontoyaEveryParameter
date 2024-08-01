package com.nickcoblentz.montoya

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import burp.api.montoya.utilities.Base64EncodingOptions
import java.awt.Component
import java.awt.event.ActionEvent
import java.util.concurrent.Executors
import javax.swing.JMenuItem

enum class PayloadType {
    REPLACE,
    MIDDLE,
    BEGINNING,
    END
}

class EveryParameter : BurpExtension, ContextMenuItemsProvider {

    private lateinit var logger: MontoyaLogger
    private lateinit var api: MontoyaApi
    private val sqliMenuItem = JMenuItem("SQLi")
    private val xssMapMenuItem = JMenuItem("XSS ASDF")
    private val xssPayloadsMenuItem = JMenuItem("XSS Payloads")
    private val blindXssImgMenuItem = JMenuItem("Blind XSS Img")
    private val allMenuItems = mutableListOf<Component>(sqliMenuItem,xssMapMenuItem,xssPayloadsMenuItem,blindXssImgMenuItem)
    private var currentHttpRequestResponseList = mutableListOf<HttpRequestResponse>()
    private val executor = Executors.newVirtualThreadPerTaskExecutor()

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
        sqliMenuItem.addActionListener({ e -> sqliActionPerformed(e) })
        xssMapMenuItem.addActionListener({ e -> xssMapActionPerformed(e) })
        xssPayloadsMenuItem.addActionListener({ e -> xssPayloadsActionPerformed(e) })
        xssPayloadsMenuItem.addActionListener({ e -> xssPayloadsActionPerformed(e) })
        blindXssImgMenuItem.addActionListener({ e -> blindXssImgActionPerformed(e) })
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

    fun sqliActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'",PayloadType.END, "SQLi '")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\"",PayloadType.END, "SQLi \"")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'+'",PayloadType.MIDDLE, "SQLi concat +'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'||'",PayloadType.MIDDLE, "SQLi concat ||'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"' '",PayloadType.MIDDLE, "SQLi concat space'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'-- ",PayloadType.END, "SQLi comment'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"')-- ",PayloadType.END, "SQLi comment)'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\"+\"",PayloadType.MIDDLE, "SQLi concat +\"")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\"||\"",PayloadType.MIDDLE, "SQLi concat ||\"")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\" \"",PayloadType.MIDDLE, "SQLi concat space\"")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\"-- ",PayloadType.END, "SQLi comment\"")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\")-- ",PayloadType.END, "SQLi comment )\"")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"' or 'a'='a' or 'a'='",PayloadType.END, "SQLi boolean a'")
        iterateThroughParametersWithPayload(myHttpRequestResponses," or 1=1 or 1=",PayloadType.END, "SQLi boolean 1'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"' or 'a'='a' or 'a'='",PayloadType.END, "SQLi boolean a\"")
        iterateThroughParametersWithPayload(myHttpRequestResponses," or 1=1 or 1=",PayloadType.END, "SQLi boolean 1\"")
        logger.debugLog("Exit")
    }

    fun xssMapActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'\">asdf",PayloadType.END, "XSS asdf")
        logger.debugLog("Exit")
    }

    fun blindXssImgActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'\"><img src=\"https://${api.collaborator().defaultPayloadGenerator().generatePayload().toString()}/blindimg.png\">asdf",PayloadType.END, "Bind XSS Img")
        logger.debugLog("Exit")
    }

    fun xssPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'\"><h2>heading here</h2>asdfh2",PayloadType.END, "XSS h2")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'\"><script>alert(1)</script>asdfalert",PayloadType.END, "XSS Alert")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'\"＞＜script＞alert(1)＜/script＞asdfutf7",PayloadType.END, "XSS UTF7")
        logger.debugLog("Exit")
    }

    fun iterateThroughParametersWithPayload(httpRequestResponses : List<HttpRequestResponse>, payload : String, type : PayloadType, annotation : String)
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

            for(parameter in httpRequest.parameters())
            {
                logger.debugLog("Found param: ${parameter.name()}, ${parameter.type()}, ${parameter.value()}")
                when(parameter.type()) {
                    HttpParameterType.URL ->
                        sendRequest(httpRequest.withUpdatedParameters(createUpdatedParameter(parameter,api.utilities().urlUtils().encode(payload))),"URL Param: ${parameter.name()}: $annotation")
                    HttpParameterType.BODY ->
                        sendRequest(httpRequest.withUpdatedParameters(createUpdatedParameter(parameter,api.utilities().urlUtils().encode(payload))),"Body Param: ${parameter.name()}: $annotation")
                    HttpParameterType.COOKIE ->
                        sendRequest(httpRequest.withUpdatedParameters(createUpdatedParameter(parameter,api.utilities().urlUtils().encode(payload))),"Cookie: ${parameter.name()}: $annotation")
                    HttpParameterType.MULTIPART_ATTRIBUTE ->
                        sendRequest(httpRequest.withUpdatedParameters(createUpdatedParameter(parameter,payload)),"mutipart Param: ${parameter.name()}: $annotation")
                    HttpParameterType.JSON ->
                        sendRequest(matchReplaceParameterInRequest(httpRequest,parameter,payload.replace("\"","\\\"")),"URL JSON: ${parameter.name()}: $annotation")
                    HttpParameterType.XML ->
                        sendRequest(matchReplaceParameterInRequest(httpRequest,parameter,api.utilities().htmlUtils().encode(payload)),"URL XML: ${parameter.name()}: $annotation")
                    HttpParameterType.XML_ATTRIBUTE ->
                        sendRequest(matchReplaceParameterInRequest(httpRequest,parameter,api.utilities().htmlUtils().encode(payload)),"URL XML Attr: ${parameter.name()}: $annotation")
                    else -> Unit
                }
            }
        }
        logger.debugLog("Exit")
    }

    fun createUpdatedParameter(parsedParameter : ParsedHttpParameter,encodedPayload : String) : HttpParameter {
        logger.debugLog("Enter")
        return HttpParameter.parameter(parsedParameter.name(),encodedPayload,parsedParameter.type())
    }

    fun matchReplaceParameterInRequest(originalRequest : HttpRequest ,parsedParameter : ParsedHttpParameter,encodedPayload : String) : HttpRequest {
        return originalRequest.withBody(originalRequest.bodyToString().replace(parsedParameter.value(),encodedPayload))
    }
    fun sendRequest(httpRequest : HttpRequest, annotation : String)
    {
        logger.debugLog("Enter")
        executor.submit {
            val annotatedHttpRequest = httpRequest.withAddedHeader("x-everyparam",api.utilities().base64Utils().encode(annotation,Base64EncodingOptions.URL).toString())
            api.http().sendRequest(annotatedHttpRequest)
        }
        logger.debugLog("Exit")
    }
}