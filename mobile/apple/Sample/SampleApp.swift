import UIKit
#if GCOMS_ENABLED
import GComs
#endif
@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let controller = UIViewController()
        controller.view.backgroundColor = .systemBackground
        let label = UILabel(frame: CGRect(x: 24, y: 100, width: 330, height: 140))
        label.numberOfLines = 0
        label.text = "GComs preview"
        controller.view.addSubview(label)
        window = UIWindow(frame: UIScreen.main.bounds)
        window?.rootViewController = controller
        window?.makeKeyAndVisible()
        #if GCOMS_ENABLED
        Task {
            do {
                let sdk = try GComs()
                label.text = "GComs preview ready"
                try await sdk.close()
            } catch { label.text = "GComs preview could not start" }
        }
        #endif
        return true
    }
}
