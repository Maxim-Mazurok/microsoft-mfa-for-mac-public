import Foundation
import LocalAuthentication

final class LocalVerification {
    private var context: LAContext?
    private var ticket: VerificationTicket?
    private var completion: ((VerificationTicket, Bool) -> Void)?
    private var timeout: DispatchWorkItem?

    func verify(ticket: VerificationTicket, allowRecentUnlock: Bool,
                completion: @escaping (VerificationTicket, Bool) -> Void) {
        cancel()
        let context = LAContext()
        context.localizedCancelTitle = "Cancel sign-in"
        // Apple permits reuse of a recent device-unlock Touch ID match only. A successful
        // previous app evaluation is not a reusable authentication grant.
        context.touchIDAuthenticationAllowableReuseDuration = allowRecentUnlock ? 30 : 0
        self.context = context; self.ticket = ticket; self.completion = completion
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { finish(false); return }
        let timeout = DispatchWorkItem { [weak self] in self?.cancel() }
        self.timeout = timeout
        DispatchQueue.main.asyncAfter(deadline: .now() + 45, execute: timeout)
        context.evaluatePolicy(.deviceOwnerAuthentication,
                               localizedReason: "Verify your identity for this Microsoft sign-in on this Mac.") { [weak self] success, _ in
            DispatchQueue.main.async { [weak self] in
                guard self?.ticket?.ticketID == ticket.ticketID else { return }
                self?.finish(success)
            }
        }
    }

    func cancel() { context?.invalidate(); finish(false) }

    private func finish(_ success: Bool) {
        timeout?.cancel(); timeout = nil
        let savedTicket = ticket, callback = completion
        context?.invalidate(); context = nil; ticket = nil; completion = nil
        if let savedTicket { callback?(savedTicket, success) }
    }
}
