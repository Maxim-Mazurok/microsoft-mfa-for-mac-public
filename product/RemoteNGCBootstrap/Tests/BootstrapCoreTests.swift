import XCTest
import Darwin
@testable import BootstrapCore

final class BootstrapCoreTests: XCTestCase {
    let now: TimeInterval = 1_800_000_000
    let tenant = "00000000-0000-4000-8000-000000000001"
    let state = String(repeating: "s", count: 43)

    func fixture(_ edit: (inout [String: Any], inout [String: String]) -> Void = { _, _ in }) throws -> Data {
        let claims = "{\"access_token\":{\"deviceid\":{\"essential\":true},\"amr\":{\"essential\":true,\"values\":[\"ngcmfa\"]},\"acrs\":{\"essential\":true,\"values\":[\"urn:user:registersecurityinfo\"]}},\"id_token\":{\"acrs\":{\"essential\":true,\"values\":[\"urn:user:registersecurityinfo\"]}}}"
        var values: [String: Any] = ["v": 1, "experiment": "NGC-B01", "tenant_id": tenant,
            "authorize_endpoint": "https://login.microsoftonline.com/\(tenant)/oauth2/v2.0/authorize", "callback_scheme": BootstrapInput.scheme,
            "callback_host": BootstrapInput.host, "callback_path": BootstrapInput.path, "state": state, "expires_at": Int(now + 600)]
        var query = ["client_id": BootstrapInput.clientID, "redirect_uri": BootstrapInput.redirect, "response_type": "code", "response_mode": "query",
            "scope": "urn:ms-drs:enterpriseregistration.windows.net/.default openid profile offline_access", "login_hint": "probe@example.invalid", "hsu": "1", "state": state,
            "code_challenge": String(repeating: "c", count: 43), "code_challenge_method": "S256", "claims": claims,
            "nux": "1", "msafed": "0", "instance_aware": "true", "is_remote_login_allowed": "true"]
        edit(&values, &query)
        var url = URLComponents(string: values["authorize_endpoint"] as! String)!
        url.queryItems = query.sorted(by: { $0.key < $1.key }).map { URLQueryItem(name: $0.key, value: $0.value) }
        values["authorize_url"] = url.string!
        return try JSONSerialization.data(withJSONObject: values, options: [.sortedKeys])
    }
    func callback(_ query: [URLQueryItem]) -> URL {
        var parts = URLComponents(string: BootstrapInput.redirect)!
        parts.queryItems = query
        return parts.url!
    }
    func testValidPrepareAndCodeCallback() throws {
        let input = try BootstrapInput(data: fixture(), now: now)
        let (data, success) = try input.callbackData(callback([.init(name: "code", value: "SYNTHETIC_CODE"), .init(name: "state", value: state)]), now: now + 10)
        XCTAssertTrue(success)
        XCTAssertEqual((try JSONSerialization.jsonObject(with: data) as? [String: Any])?["experiment"] as? String, "NGC-B01")
    }
    func testOAuthErrorSavedWithoutBecomingSuccess() throws {
        let input = try BootstrapInput(data: fixture(), now: now)
        let (_, success) = try input.callbackData(callback([.init(name: "error", value: "access_denied"), .init(name: "error_description", value: "Synthetic only"), .init(name: "state", value: state)]), now: now + 1)
        XCTAssertFalse(success)
    }
    func testInstanceAwareMetadataNeverChangesRequestDestination() throws {
        let input = try BootstrapInput(data: fixture(), now: now)
        let (_, success) = try input.callbackData(callback([.init(name: "code", value: "SYNTHETIC_CODE"), .init(name: "state", value: state), .init(name: "cloud_instance_host_name", value: "metadata.example.invalid"), .init(name: "cloud_graph_host_name", value: "other.example.invalid"), .init(name: "cloud_instance_name", value: "metadata.example.invalid")]), now: now + 1)
        XCTAssertTrue(success)
        XCTAssertEqual(input.authorizeURL.host, "login.microsoftonline.com")
    }
    func testRejectUntrustedDestinationAndMismatchedTenant() throws {
        for endpoint in ["http://login.microsoftonline.com/\(tenant)/oauth2/v2.0/authorize", "https://login.microsoftonline.com.evil.invalid/\(tenant)/oauth2/v2.0/authorize", "https://login.microsoftonline.com:443/\(tenant)/oauth2/v2.0/authorize", "https://login.microsoftonline.com/00000000-0000-4000-8000-000000000002/oauth2/v2.0/authorize", "https://login.microsoftonline.com/\(tenant)/oauth2/authorize"] {
            XCTAssertThrowsError(try BootstrapInput(data: fixture { value, _ in value["authorize_endpoint"] = endpoint }, now: now))
        }
    }
    func testAcceptOnlyTracedProductionAuthorityShapes() throws {
        for host in ["login.microsoftonline.com", "login.windows.net", "login.microsoft.com"] {
            for segment in [tenant, "common", "organizations"] {
                XCTAssertNoThrow(try BootstrapInput(data: fixture { value, _ in value["authorize_endpoint"] = "https://\(host)/\(segment)/oauth2/v2.0/authorize" }, now: now))
            }
        }
    }
    func testRejectAlteredPKCEClientRedirectAndClaims() throws {
        for (key, value) in ["client_id": "other", "redirect_uri": "msauth://other/path", "response_type": "token", "response_mode": "fragment", "state": String(repeating: "x", count: 43), "code_challenge_method": "plain", "code_challenge": "small", "resource": "https://graph.microsoft.com", "claims": "{}", "scope": "openid", "login_hint": "probe", "hsu": "0"] {
            XCTAssertThrowsError(try BootstrapInput(data: fixture { _, query in query[key] = value }, now: now))
        }
        XCTAssertThrowsError(try BootstrapInput(data: fixture { _, query in query["claims"] = query["claims"]!.replacingOccurrences(of: "true", with: "1") }, now: now))
    }
    func testExactMSALResourceConversionAndDefaultScopes() throws {
        for resource in ["urn:ms-drs:enterpriseregistration.windows.net", "https://enterpriseregistration.windows.net", "https://enterpriseregistration.windows.net/"] {
            for scopes in [resource + "/.default openid profile offline_access", "offline_access profile " + resource + "/.default openid"] {
                XCTAssertNoThrow(try BootstrapInput(data: fixture { _, query in query["scope"] = scopes }, now: now))
            }
        }
        for scope in ["openid profile offline_access", "urn:ms-drs:enterpriseregistration.windows.net/.default openid profile profile", "urn:ms-drs:enterpriseregistration.windows.net/.default openid profile offline_access User.Read", "https://graph.microsoft.com/.default openid profile offline_access", "urn:ms-drs:enterpriseregistration.windows.net/.default  openid profile offline_access"] {
            XCTAssertThrowsError(try BootstrapInput(data: fixture { _, query in query["scope"] = scope }, now: now))
        }
    }
    func testRejectExpiredAndExcessiveTTLAndBooleanVersion() throws {
        for expiry in [now, now - 1, now + 601] {
            XCTAssertThrowsError(try BootstrapInput(data: fixture { value, _ in value["expires_at"] = expiry }, now: now))
        }
        XCTAssertThrowsError(try BootstrapInput(data: fixture { value, _ in value["v"] = true }, now: now))
    }
    func testRejectDuplicateAuthorizeParameterAndUnknownInputKey() throws {
        var value = try JSONSerialization.jsonObject(with: fixture()) as! [String: Any]
        value["authorize_url"] = (value["authorize_url"] as! String) + "&state=" + state
        XCTAssertThrowsError(try BootstrapInput(data: JSONSerialization.data(withJSONObject: value), now: now))
        value = try JSONSerialization.jsonObject(with: fixture()) as! [String: Any]
        value["code_verifier"] = "MUST_STAY_WITH_PROTOCOL_PREPARER"
        XCTAssertThrowsError(try BootstrapInput(data: JSONSerialization.data(withJSONObject: value), now: now))
    }
    func testFormSpacesAndEncodedLiteralPlusAreDistinct() throws {
        var value = try JSONSerialization.jsonObject(with: fixture { _, query in
            let claims = try! JSONSerialization.jsonObject(with: Data(query["claims"]!.utf8))
            query["claims"] = String(data: try! JSONSerialization.data(withJSONObject: claims, options: [.prettyPrinted]), encoding: .utf8)!
            query["login_hint"] = "probe+research@example.invalid"
        }) as! [String: Any]
        value["authorize_url"] = (value["authorize_url"] as! String).replacingOccurrences(of: "%20", with: "+").replacingOccurrences(of: "probe+research", with: "probe%2Bresearch")
        XCTAssertNoThrow(try BootstrapInput(data: JSONSerialization.data(withJSONObject: value), now: now))
        let parts = URLComponents(string: "https://example.invalid/?encoded=a%2Bb&space=a+b")!
        let query = try BootstrapInput.uniqueQuery(BootstrapInput.formQueryItems(parts)!, error: .invalidInput)
        XCTAssertEqual(query["encoded"], "a+b")
        XCTAssertEqual(query["space"], "a b")
    }
    func testRejectDuplicateAndWrongStateCallback() throws {
        let input = try BootstrapInput(data: fixture(), now: now)
        for items: [URLQueryItem] in [
            [.init(name: "code", value: "a"), .init(name: "code", value: "b"), .init(name: "state", value: state)],
            [.init(name: "code", value: "a"), .init(name: "state", value: "wrong")],
            [.init(name: "code", value: "a"), .init(name: "error", value: "denied"), .init(name: "state", value: state)],
            [.init(name: "access_token", value: "implicit_response_rejected"), .init(name: "state", value: state)]
        ] { XCTAssertThrowsError(try input.callbackData(callback(items), now: now + 1)) }
    }
    func testRejectCallbackDestinationFragmentAndExpiry() throws {
        let input = try BootstrapInput(data: fixture(), now: now)
        let valid = callback([.init(name: "code", value: "SYNTHETIC"), .init(name: "state", value: state)]).absoluteString
        for invalid in [valid.replacingOccurrences(of: "com.azure.authenticator", with: "other.invalid"), valid.replacingOccurrences(of: "%3D", with: "%253D"), valid + "#fragment", valid.replacingOccurrences(of: "msauth:", with: "https:")] {
            XCTAssertThrowsError(try input.callbackData(URL(string: invalid)!, now: now + 1))
        }
        XCTAssertThrowsError(try input.callbackData(URL(string: valid)!, now: now + 600))
    }
    func testCallbackPathEquivalentEscapesKeepExactDecodedIdentity() throws {
        let input = try BootstrapInput(data: fixture(), now: now)
        let valid = callback([.init(name: "code", value: "SYNTHETIC"), .init(name: "state", value: state)]).absoluteString
        for spelling in ["%3D", "%3d", "="] {
            XCTAssertNoThrow(try input.callbackData(URL(string: valid.replacingOccurrences(of: "%3D", with: spelling))!, now: now + 1))
        }
        for invalid in ["/ho040S3ffZkmxqtQrSwpTVOn9r0%", "/ho040S3ffZkmxqtQrSwpTVOn9r0%GG", "/ho040S3ffZkmxqtQrSwpTVOn9r0%253D", "/ho040S3ffZkmxqtQrSwpTVOn9r0==", "/other/"] {
            XCTAssertFalse(BootstrapInput.callbackPathMatches(invalid))
        }
    }
    func testUnknownInertResponseMetadataDoesNotSelectDestination() throws {
        let input = try BootstrapInput(data: fixture(), now: now)
        let url = callback([.init(name: "code", value: "SYNTHETIC"), .init(name: "state", value: state),
            .init(name: "redirect_uri", value: "https://untrusted.invalid/callback"), .init(name: "token_endpoint", value: "https://untrusted.invalid/token"),
            .init(name: "resource", value: "untrusted"), .init(name: "new_server_metadata", value: "")])
        XCTAssertTrue(try input.callbackData(url, now: now + 1).1)
        XCTAssertEqual(input.authorizeURL.host, "login.microsoftonline.com")
        let duplicate = URL(string: url.absoluteString + "&new_server_metadata=duplicate")!
        XCTAssertThrowsError(try input.callbackData(duplicate, now: now + 1))
    }
    func testCallbackRejectsInvalidUTF8AndNonASCIIOrEmptyCode() throws {
        let input = try BootstrapInput(data: fixture(), now: now)
        for code in ["", "nonascii-é", "line\nfeed"] {
            XCTAssertThrowsError(try input.callbackData(callback([.init(name: "code", value: code), .init(name: "state", value: state)]), now: now + 1))
        }
        XCTAssertThrowsError(try input.callbackData(URL(string: BootstrapInput.redirect + "?code=%FF&state=" + state)!, now: now + 1))
        XCTAssertThrowsError(try input.callbackData(URL(string: BootstrapInput.redirect + "?")!, now: now + 1))
    }
    func testAuthorizationCodeBoundMatchesInterpreter() throws {
        let input = try BootstrapInput(data: fixture(), now: now)
        XCTAssertNoThrow(try input.callbackData(callback([.init(name: "code", value: String(repeating: "s", count: 16384)), .init(name: "state", value: state)]), now: now + 1))
        XCTAssertThrowsError(try input.callbackData(callback([.init(name: "code", value: String(repeating: "s", count: 16385)), .init(name: "state", value: state)]), now: now + 1))
    }

    func temporaryDirectory() throws -> URL {
        // Foundation intentionally abbreviates /private/var back to /var, a
        // symlink our descriptor walker correctly rejects. Use realpath here.
        let resolved = realpath(FileManager.default.temporaryDirectory.path, nil)!
        let root = String(cString: resolved); free(resolved)
        let dir = URL(fileURLWithPath: root).appendingPathComponent("ngc-native-synthetic-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }
    func inputFile(_ dir: URL) throws -> URL {
        let file = dir.appendingPathComponent("auth-input.json")
        try fixture().write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        return file
    }
    func testPrivateStorageExclusiveLockAndOutput() throws {
        let dir = try temporaryDirectory(), file = try inputFile(dir), output = dir.appendingPathComponent("auth-callback.json")
        let attempt = try PrivateAttempt(inputPath: file.path, outputPath: output.path)
        XCTAssertEqual(try attempt.readInput(), try fixture())
        try attempt.claimOneSession()
        XCTAssertThrowsError(try attempt.claimOneSession())
        try attempt.saveCallback(Data("SYNTHETIC_ONLY".utf8))
        XCTAssertThrowsError(try attempt.saveCallback(Data()))
        let perms = try FileManager.default.attributesOfItem(atPath: output.path)[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o600)
    }
    func testPrivateStorageRejectPermissionsAndSymlinks() throws {
        let dir = try temporaryDirectory(), file = try inputFile(dir), output = dir.appendingPathComponent("auth-callback.json")
        let attempt = try PrivateAttempt(inputPath: file.path, outputPath: output.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        XCTAssertThrowsError(try attempt.readInput())
        let link = dir.appendingPathComponent("link-input.json")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        let linked = try PrivateAttempt(inputPath: link.path, outputPath: output.path)
        XCTAssertThrowsError(try linked.readInput())
        try FileManager.default.createSymbolicLink(at: output, withDestinationURL: file)
        XCTAssertThrowsError(try attempt.claimOneSession())
        XCTAssertThrowsError(try attempt.saveCallback(Data()))
    }
    func testPrivateStorageRejectBroadDirectoryAndDifferentOutputParent() throws {
        let dir = try temporaryDirectory(), file = try inputFile(dir), other = try temporaryDirectory()
        XCTAssertThrowsError(try PrivateAttempt(inputPath: file.path, outputPath: other.appendingPathComponent("callback.json").path))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.path)
        XCTAssertThrowsError(try PrivateAttempt(inputPath: file.path, outputPath: dir.appendingPathComponent("callback.json").path))
    }
    func recorderFixture() throws -> (URL, NativeSessionRecorder, BootstrapInput) {
        let dir = try temporaryDirectory(), file = try inputFile(dir)
        let attempt = try PrivateAttempt(inputPath: file.path, outputPath: dir.appendingPathComponent("callback.json").path)
        let recorder = try NativeSessionRecorder(attempt: attempt)
        return (dir, recorder, try BootstrapInput(data: fixture(), now: now))
    }
    func report(_ dir: URL) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: Data(contentsOf: dir.appendingPathComponent("native-result.json"))) as! [String: Any]
    }
    func testNativeLifecycleSuccessfulCallbackPersistsCandidateAndTerminalReceiptOnce() throws {
        let (dir, recorder, input) = try recorderFixture()
        try recorder.ready(); try recorder.sessionDidStart()
        let url = callback([.init(name: "code", value: "SYNTHETIC"), .init(name: "state", value: state), .init(name: "cloud_instance_name", value: "microsoftonline.com")])
        XCTAssertEqual(try recorder.complete(input: input, url: url, now: now + 1), "callback_saved")
        let receipt = try report(dir)
        XCTAssertEqual(receipt["terminal"] as? Bool, true)
        XCTAssertEqual(receipt["callback_saved"] as? Bool, true)
        XCTAssertEqual(receipt["callback_candidate_saved"] as? Bool, true)
        XCTAssertTrue(FileManager.default.fileExists(atPath: dir.appendingPathComponent("callback.json").path))
        let prior = try Data(contentsOf: dir.appendingPathComponent("native-result.json"))
        XCTAssertEqual(try recorder.finish("cancelled"), "callback_saved")
        XCTAssertEqual(try Data(contentsOf: dir.appendingPathComponent("native-result.json")), prior)
        for name in ["native-result.json", "native-callback-candidate.json", "callback.json"] {
            XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: dir.appendingPathComponent(name).path)[.posixPermissions] as? Int, 0o600)
        }
    }
    func testNativeLifecycleWrongStateHasPrivateCandidateAndNoAcceptedCallback() throws {
        let (dir, recorder, input) = try recorderFixture()
        try recorder.sessionDidStart()
        let url = callback([.init(name: "code", value: "SYNTHETIC"), .init(name: "state", value: "wrong")])
        XCTAssertEqual(try recorder.complete(input: input, url: url, now: now + 1), "callback_state_mismatch")
        let receipt = try report(dir)
        XCTAssertEqual(receipt["callback_received"] as? Bool, true)
        XCTAssertEqual(receipt["callback_candidate_saved"] as? Bool, true)
        XCTAssertEqual(receipt["callback_saved"] as? Bool, false)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent("callback.json").path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: dir.appendingPathComponent("native-callback-candidate.json").path))
        let text = String(data: try Data(contentsOf: dir.appendingPathComponent("native-result.json")), encoding: .utf8)!
        XCTAssertFalse(text.contains("SYNTHETIC")); XCTAssertFalse(text.contains("msauth"))
    }
    func testNativeLifecycleDistinctTerminalStatusesAndBoundedSystemErrors() throws {
        for code in ["cancelled", "window_closed", "invalid_input", "input_expired", "session_start_failed"] {
            let (dir, recorder, _) = try recorderFixture()
            XCTAssertEqual(try recorder.finish(code), code)
            let receipt = try report(dir)
            XCTAssertEqual(receipt["status"] as? String, code)
            XCTAssertEqual(receipt["terminal"] as? Bool, true)
            XCTAssertEqual(receipt["callback_saved"] as? Bool, false)
        }
        for (domain, numeric, expected) in [("authentication_services", 1, "authentication_cancelled"), ("authentication_services", 2, "authentication_presentation_context_missing"), ("authentication_services", 3, "authentication_presentation_context_invalid"), ("untrusted-domain-must-not-be-retained", 999999, "authentication_session_failed")] {
            let (dir, recorder, input) = try recorderFixture()
            try recorder.sessionDidStart()
            XCTAssertEqual(try recorder.complete(input: input, url: nil, systemErrorDomain: domain, systemErrorCode: numeric, now: now + 1), expected)
            let receipt = try report(dir)
            XCTAssertEqual(receipt["system_error_domain"] as? String, domain == "authentication_services" ? domain : "other")
            if numeric == 999999 { XCTAssertTrue(receipt["system_error_code"] is NSNull) }
        }
    }
    func testNativeReceiptCannotOverwritePriorAttemptOrFollowSymlink() throws {
        let (dir, _, _) = try recorderFixture()
        let attempt = try PrivateAttempt(inputPath: dir.appendingPathComponent("auth-input.json").path, outputPath: dir.appendingPathComponent("callback.json").path)
        XCTAssertThrowsError(try NativeSessionRecorder(attempt: attempt))
        let second = try temporaryDirectory(), file = try inputFile(second)
        try FileManager.default.createSymbolicLink(at: second.appendingPathComponent("native-result.json"), withDestinationURL: file)
        let linked = try PrivateAttempt(inputPath: file.path, outputPath: second.appendingPathComponent("callback.json").path)
        XCTAssertThrowsError(try NativeSessionRecorder(attempt: linked))
    }
}
