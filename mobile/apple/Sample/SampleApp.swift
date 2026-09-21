import UIKit
#if GCOMS_ENABLED
import GComs
#endif
#if GCOMS_PUSH
import GComsPush
#endif
@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    #if GCOMS_PUSH
    // The operator supplies tickets/network configuration in a real app.
    private var push: PushGateway?
    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        // Preview intentionally performs no live registration.
    }
    func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any],
        fetchCompletionHandler completion: @escaping (UIBackgroundFetchResult) -> Void) {
        _ = PushGateway.hintReference(userInfo)
        completion(.noData)
    }
    #endif
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
                #if GCOMS_PUSH
                push = try PushGateway(origin: URL(string: "https://push.example.invalid")!,
                    storage: KeychainPushStorage(profile: "preview"))
                #endif
                label.text = "GComs preview ready"
                try await sdk.close()
            } catch { label.text = "GComs preview could not start" }
        }
        #endif
        return true
    }
}
