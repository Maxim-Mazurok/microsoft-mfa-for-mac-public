import Foundation
import LocalAuthentication

let context = LAContext()
var error: NSError?
let available = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
if CommandLine.arguments == [CommandLine.arguments[0], "--check"] {
    print(available ? "available" : "unavailable")
    exit(0)
}
guard CommandLine.arguments == [CommandLine.arguments[0], "--verify"], available else {
    print("unavailable")
    exit(1)
}
context.evaluatePolicy(.deviceOwnerAuthentication,
                       localizedReason: "Verify your identity for the Microsoft MFA research request you are approving.") { success, _ in
    DispatchQueue.main.async {
        print(success ? "authenticated" : "not_authenticated")
        exit(success ? 0 : 1)
    }
}
DispatchQueue.main.asyncAfter(deadline: .now() + 45) {
    context.invalidate()
    print("expired")
    exit(1)
}
RunLoop.main.run()
