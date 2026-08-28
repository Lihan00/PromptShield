# secure_codes.py

SECURE_CODE_DATABASE = {
    "SQL Injection": {
        "language": "Java/Spring",
        "vulnerable_code": "String query = \"SELECT * FROM users WHERE user_id = '\" + userId + \"'\";\nStatement stmt = connection.createStatement();\nResultSet rs = stmt.executeQuery(query);",
        "secure_code": "String query = \"SELECT * FROM users WHERE user_id = ?\";\nPreparedStatement pstmt = connection.prepareStatement(query);\npstmt.setString(1, userId);\nResultSet rs = pstmt.executeQuery();"
    },
    "Command Injection": {
        "language": "Java/Spring",
        "vulnerable_code": "String cmd = \"ping -c 1 \" + userIp;\nProcess process = Runtime.getRuntime().exec(cmd);",
        "secure_code": "if (!Pattern.matches(\"^[0-9.]+$\", userIp)) {\n    throw new IllegalArgumentException(\"Invalid IP\");\n}\nString[] cmd = {\"ping\", \"-c\", \"1\", userIp};\nProcess process = new ProcessBuilder(cmd).start();"
    },
    "Broken Access Control / IDOR": {
        "language": "Java/Spring",
        "vulnerable_code": "@GetMapping(\"/user/info\")\npublic User getUserInfo(@RequestParam(\"userId\") String userId) {\n    return userService.findById(userId);\n}",
        "secure_code": "@GetMapping(\"/user/info\")\npublic User getUserInfo(@RequestParam(\"userId\") String userId, HttpSession session) {\n    String loginUser = (String) session.getAttribute(\"loginUser\");\n    if (!loginUser.equals(userId)) {\n        throw new AccessDeniedException(\"권한 없음\");\n    }\n    return userService.findById(userId);\n}"
    },
    "SSRF": {
        "language": "Java/Spring",
        "vulnerable_code": "String targetUrl = request.getParameter(\"url\");\nRestTemplate rest = new RestTemplate();\nString res = rest.getForObject(targetUrl, String.class);",
        "secure_code": "String targetUrl = request.getParameter(\"url\");\nif (!targetUrl.startsWith(\"https://api.trusted.com\")) {\n    throw new IllegalArgumentException(\"허용되지 않은 도메인\");\n}"
    },
    "XSS": {
        "language": "Java/Spring",
        "vulnerable_code": "model.addAttribute(\"userInput\", userInput);",
        "secure_code": "String safeInput = HtmlUtils.htmlEscape(userInput);\nmodel.addAttribute(\"userInput\", safeInput);"
    },
    "Path Traversal": {
        "language": "Java/Spring",
        "vulnerable_code": "String fileName = request.getParameter(\"filename\");\nFile file = new File(\"/var/uploads/\" + fileName);",
        "secure_code": "Path basePath = Paths.get(\"/var/uploads\").toAbsolutePath().normalize();\nPath targetPath = basePath.resolve(fileName).normalize();\nif (!targetPath.startsWith(basePath)) {\n    throw new SecurityException(\"잘못된 경로 접근\");\n}"
    },
    "File Upload": {
        "language": "Java/Spring",
        "vulnerable_code": "MultipartFile file = request.getFile(\"file\");\nfile.transferTo(new File(\"/var/www/upload/\" + file.getOriginalFilename()));",
        "secure_code": "MultipartFile file = request.getFile(\"file\");\nString ext = getFileExtension(file.getOriginalFilename());\nif (!ext.equalsIgnoreCase(\"jpg\")) {\n    throw new IllegalArgumentException(\"허용되지 않는 형식\");\n}\nString safeName = UUID.randomUUID().toString() + \".\" + ext;\nfile.transferTo(new File(\"/var/www/upload/\" + safeName));"
    }
}