package com.krish.sentinel_guard.waf.payload;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import java.io.StringReader;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class PayloadNormalizer {

    private static final Pattern BOUNDARY_PATTERN = Pattern.compile("boundary\\s*=\\s*\"?([^;\"\\s]+)\"?", Pattern.CASE_INSENSITIVE);
    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/]{16,}={0,2}$");
    private static final Pattern SUSPICIOUS = Pattern.compile("[<>'\"`$\\\\]|/etc/|\\bor\\b\\s+1\\s*=\\s*1|\\{\\{");

    private final ObjectMapper objectMapper = new ObjectMapper();

    public List<PayloadSurface> normalize(
            String path,
            String queryString,
            Map<String, String> headers,
            byte[] body,
            String contentType,
            Charset charset) {

        List<PayloadSurface> surfaces = new ArrayList<>();
        Charset cs = charset != null ? charset : StandardCharsets.UTF_8;
        byte[] bodyBytes = body != null ? body : new byte[0];
        String rawBody = bodyBytes.length == 0 ? "" : new String(bodyBytes, cs);
        String ct = contentType != null ? contentType.toLowerCase(Locale.ROOT) : "";

        addPathSurfaces(path, surfaces);
        addQuerySurfaces(queryString, surfaces);
        addHeaderSurfaces(headers, surfaces);

        if (!rawBody.isBlank()) {
            surfaces.add(new PayloadSurface("HTTP Request Body", rawBody));
        }

        if (ct.contains("json")) {
            extractJson(rawBody, surfaces);
        } else if (ct.contains("xml") || ct.contains("soap")) {
            extractXml(rawBody, surfaces);
        } else if (ct.contains("application/x-www-form-urlencoded")) {
            extractForm(rawBody, "Form field", surfaces);
        } else if (ct.contains("multipart/form-data")) {
            extractMultipart(rawBody, contentType, surfaces);
        }

        if (!ct.contains("json") && looksLikeJson(rawBody)) {
            extractJson(rawBody, surfaces);
        }
        if (!ct.contains("xml") && looksLikeXml(rawBody)) {
            extractXml(rawBody, surfaces);
        }

        addBase64Surfaces(new ArrayList<>(surfaces), surfaces);
        return surfaces;
    }

    private void addPathSurfaces(String path, List<PayloadSurface> surfaces) {
        if (path == null || path.isBlank()) {
            return;
        }
        surfaces.add(new PayloadSurface("URI Path", path));
        String decoded = urlDecode(path);
        if (!decoded.equals(path)) {
            surfaces.add(new PayloadSurface("URI Path (decoded)", decoded));
        }
        String twice = urlDecode(decoded);
        if (!twice.equals(decoded)) {
            surfaces.add(new PayloadSurface("URI Path (double-decoded)", twice));
        }
    }

    private void addQuerySurfaces(String queryString, List<PayloadSurface> surfaces) {
        if (queryString == null || queryString.isBlank()) {
            return;
        }
        surfaces.add(new PayloadSurface("Query String", queryString));
        String decoded = urlDecode(queryString);
        surfaces.add(new PayloadSurface("Query String (decoded)", decoded));
        extractForm(decoded, "Query param", surfaces);
    }

    private void addHeaderSurfaces(Map<String, String> headers, List<PayloadSurface> surfaces) {
        if (headers == null) {
            return;
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null) {
                continue;
            }
            String name = entry.getKey();
            String value = entry.getValue();
            surfaces.add(new PayloadSurface("HTTP Header [" + name + "]", value));
            if ("cookie".equalsIgnoreCase(name)) {
                extractCookies(value, surfaces);
            }
        }
    }

    private void extractCookies(String cookieHeader, List<PayloadSurface> surfaces) {
        for (String piece : cookieHeader.split(";")) {
            String trimmed = piece.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int eq = trimmed.indexOf('=');
            if (eq <= 0) {
                surfaces.add(new PayloadSurface("Cookie", trimmed));
                continue;
            }
            String cname = trimmed.substring(0, eq).trim();
            String cval = urlDecode(trimmed.substring(eq + 1).trim());
            surfaces.add(new PayloadSurface("Cookie [" + cname + "]", cval));
        }
    }

    private void extractForm(String encoded, String locationPrefix, List<PayloadSurface> surfaces) {
        if (encoded == null || encoded.isBlank()) {
            return;
        }
        for (String pair : encoded.split("&")) {
            if (pair.isBlank()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String name = urlDecode(eq >= 0 ? pair.substring(0, eq) : pair);
            String value = urlDecode(eq >= 0 ? pair.substring(eq + 1) : "");
            surfaces.add(new PayloadSurface(locationPrefix + " [" + name + "]", value));
            surfaces.add(new PayloadSurface(locationPrefix + " name", name));
        }
    }

    private void extractJson(String raw, List<PayloadSurface> surfaces) {
        if (raw == null || raw.isBlank()) {
            return;
        }
        try {
            JsonNode root = objectMapper.readTree(raw);
            walkJson(root, "", surfaces);
        } catch (Exception ignored) {
            // Raw body already inspected.
        }
    }

    private void walkJson(JsonNode node, String path, List<PayloadSurface> surfaces) {
        if (node == null || node.isNull()) {
            return;
        }
        if (node.isObject()) {
            node.fields().forEachRemaining(e -> {
                String next = path.isEmpty() ? e.getKey() : path + "." + e.getKey();
                surfaces.add(new PayloadSurface("JSON key [" + next + "]", e.getKey()));
                walkJson(e.getValue(), next, surfaces);
            });
            return;
        }
        if (node.isArray()) {
            int i = 0;
            for (JsonNode child : node) {
                walkJson(child, path + "[" + i++ + "]", surfaces);
            }
            return;
        }
        surfaces.add(new PayloadSurface("JSON field [" + (path.isEmpty() ? "value" : path) + "]", node.asText()));
    }

    private void extractXml(String raw, List<PayloadSurface> surfaces) {
        if (raw == null || raw.isBlank()) {
            return;
        }
        XMLInputFactory factory = XMLInputFactory.newInstance();
        try {
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        } catch (Exception ignored) {
            // Some StAX implementations reject these properties.
        }
        try {
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(raw));
            while (reader.hasNext()) {
                int event = reader.next();
                if (event == XMLStreamConstants.START_ELEMENT) {
                    for (int i = 0; i < reader.getAttributeCount(); i++) {
                        surfaces.add(new PayloadSurface(
                                "XML attribute [" + reader.getLocalName() + "." + reader.getAttributeLocalName(i) + "]",
                                reader.getAttributeValue(i)));
                    }
                } else if (event == XMLStreamConstants.CHARACTERS || event == XMLStreamConstants.CDATA) {
                    String text = reader.getText();
                    if (text != null && !text.isBlank()) {
                        surfaces.add(new PayloadSurface("XML text", text.trim()));
                    }
                }
            }
            reader.close();
        } catch (Exception ignored) {
            // Raw body already inspected; XXE gadgets still match on the string.
        }
    }

    private void extractMultipart(String raw, String contentType, List<PayloadSurface> surfaces) {
        Matcher matcher = BOUNDARY_PATTERN.matcher(contentType != null ? contentType : "");
        if (!matcher.find()) {
            return;
        }
        String boundary = matcher.group(1);
        String delimiter = "--" + boundary;
        String[] parts = raw.split(Pattern.quote(delimiter));
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.isEmpty() || trimmed.equals("--")) {
                continue;
            }
            int sep = indexOfHeaderBodySeparator(trimmed);
            String headers = sep >= 0 ? trimmed.substring(0, sep) : "";
            String body = sep >= 0 ? trimmed.substring(sep).strip() : trimmed;
            String name = headerValue(headers, "name");
            String filename = headerValue(headers, "filename");
            if (name != null) {
                surfaces.add(new PayloadSurface("Multipart name", name));
            }
            if (filename != null) {
                surfaces.add(new PayloadSurface("Multipart filename", filename));
            }
            if (!body.isBlank()) {
                String loc = name != null ? "Multipart field [" + name + "]" : "Multipart part";
                surfaces.add(new PayloadSurface(loc, body));
                if (looksLikeJson(body)) {
                    extractJson(body, surfaces);
                }
                if (looksLikeXml(body)) {
                    extractXml(body, surfaces);
                }
            }
        }
    }

    private void addBase64Surfaces(List<PayloadSurface> snapshot, List<PayloadSurface> surfaces) {
        for (PayloadSurface surface : snapshot) {
            String value = surface.value();
            if (value == null) {
                continue;
            }
            String compact = value.replaceAll("\\s+", "");
            if (compact.length() < 16 || compact.length() > 8192 || !BASE64_PATTERN.matcher(compact).matches()) {
                continue;
            }
            try {
                byte[] decodedBytes = Base64.getDecoder().decode(compact);
                String decoded = new String(decodedBytes, StandardCharsets.UTF_8);
                if (SUSPICIOUS.matcher(decoded).find() || looksLikeJson(decoded) || looksLikeXml(decoded)) {
                    surfaces.add(new PayloadSurface("Base64[" + surface.location() + "]", decoded));
                    if (looksLikeJson(decoded)) {
                        extractJson(decoded, surfaces);
                    }
                    if (looksLikeXml(decoded)) {
                        extractXml(decoded, surfaces);
                    }
                }
            } catch (Exception ignored) {
                // Not valid Base64.
            }
        }
    }

    private static boolean looksLikeJson(String raw) {
        if (raw == null) {
            return false;
        }
        String t = raw.trim();
        return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
    }

    private static boolean looksLikeXml(String raw) {
        return raw != null && raw.trim().startsWith("<");
    }

    private static String urlDecode(String input) {
        if (input == null) {
            return "";
        }
        try {
            return URLDecoder.decode(input.replace("+", "%2B"), StandardCharsets.UTF_8).replace("%2B", "+");
        } catch (Exception e) {
            try {
                return URLDecoder.decode(input, StandardCharsets.UTF_8);
            } catch (Exception ignored) {
                return input;
            }
        }
    }

    private static int indexOfHeaderBodySeparator(String part) {
        int crlf = part.indexOf("\r\n\r\n");
        if (crlf >= 0) {
            return crlf + 4;
        }
        int lf = part.indexOf("\n\n");
        return lf >= 0 ? lf + 2 : -1;
    }

    private static String headerValue(String headers, String attr) {
        Pattern p = Pattern.compile(attr + "\\s*=\\s*\"([^\"]*)\"|" + attr + "\\s*=\\s*([^;\\s]+)", Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(headers);
        if (!m.find()) {
            return null;
        }
        return m.group(1) != null ? m.group(1) : m.group(2);
    }
}
