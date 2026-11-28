import SafariServices
import Foundation

@objc(SafariWebExtensionHandler)
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        let input = context.inputItems.first as? NSExtensionItem
        let message = input?.userInfo?[SFExtensionMessageKey]
        let response = BrowserBridge().handle(message as Any)
        let item = NSExtensionItem()
        item.userInfo = [SFExtensionMessageKey: response]
        context.completeRequest(returningItems: [item], completionHandler: nil)
    }
}
