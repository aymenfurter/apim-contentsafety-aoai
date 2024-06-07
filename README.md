```xml
  <policies>
      <inbound>
          <base />
          <set-header name="api-key" exists-action="delete" />
          <authentication-managed-identity resource="https://cognitiveservices.azure.com" output-token-variable-name="msi-access-token" client-id="{{uami-client-id}}" ignore-error="false" />
          <set-header name="Authorization" exists-action="override">
              <value>@("Bearer " + (string)context.Variables["msi-access-token"])</value>
          </set-header>
          <set-backend-service base-url="https://openai3-xxx.openai.azure.com/openai" />
      </inbound>
      <backend>
          <forward-request buffer-request-body="true" />
      </backend>
      <outbound>
          <base />
          <send-request mode="new" response-variable-name="contentSafetyResponse" timeout="20" ignore-error="false">
              <set-url>{{content-safety-endpoint}}contentsafety/text:analyze?api-version=2023-10-01</set-url>
              <set-method>POST</set-method>
              <set-header name="Ocp-Apim-Subscription-Key" exists-action="override">
                  <value>{{content-safety-key}}</value>
              </set-header>
              <set-header name="Content-Type" exists-action="override">
                  <value>application/json</value>
              </set-header>
              <set-body>@{
                  var requestBody = context.Request.Body.As<string>(preserveContent: true);
                  var responseBody = context.Response.Body.As<string>(preserveContent: true);
                  var sanitizedRequestBody = System.Text.RegularExpressions.Regex.Replace(requestBody, "[{}\\[\\]\"]", "");
                  var sanitizedResponseBody = System.Text.RegularExpressions.Regex.Replace(responseBody, "[{}\\[\\]\"]", "");
                  return $"{{\"text\":\"{sanitizedRequestBody.Replace("\n", "").Replace("\\", "\\\\")} {sanitizedResponseBody.Replace("\n", "").Replace("\\", "\\\\")}\"}}";
              }</set-body>
          </send-request>
          <choose>
              <when condition="@{
                  var contentSafetyResponse = (IResponse)context.Variables["contentSafetyResponse"];
                  var responseBodyString = contentSafetyResponse.Body.As<string>(preserveContent: true);
                  var threshold = int.Parse(context.Request.Headers.GetValueOrDefault("X-Threshold", "8"));
                  var matches = System.Text.RegularExpressions.Regex.Matches(responseBodyString, @"\d+");
                  return matches.Cast<System.Text.RegularExpressions.Match>().Any(match => int.Parse(match.Value) > threshold);
              }">
                  <return-response>
                      <set-status code="403" reason="Content Safety Policy Violation" />
                      <set-body>{"error":"The content of the response has been flagged for potentially harmful content and exceeds the allowed severity level."}</set-body>
                  </return-response>
              </when>
          </choose>
      </outbound>
      <on-error>
          <base />
      </on-error>
  </policies>
```
