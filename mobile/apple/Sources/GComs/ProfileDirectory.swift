import Foundation

public enum ProfileDirectory {
    /// The runtime creates its own files inside this private, protected directory.
    public static func prepare(name: String) throws -> URL {
        guard name.range(of: #"^[A-Za-z0-9_-]{1,64}$"#, options: .regularExpression) != nil else {
            throw GComsError.native("Invalid profile name")
        }
        var directory = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            .appendingPathComponent("GComs", isDirectory: true).appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700, .protectionKey: FileProtectionType.complete])
        try FileManager.default.setAttributes([.posixPermissions: 0o700, .protectionKey: FileProtectionType.complete],
            ofItemAtPath: directory.path)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try directory.setResourceValues(values)
        return directory.appendingPathComponent("profile")
    }
}
