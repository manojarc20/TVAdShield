package hev.htproxy;

/**
 * JNI signature bridge for the pinned HEV Android library.
 *
 * The native JNI_OnLoad registers its methods to this exact package and class name.
 * The VPN service must pass a duplicated TUN descriptor and call TProxyStopService()
 * before closing its owning ParcelFileDescriptor. This bridge is not started by the app yet.
 */
public final class TProxyService {
    private TProxyService() { }

    static {
        System.loadLibrary("hev-socks5-tunnel");
    }

    public static native boolean TProxyStartService(String configPath, int fd);
    public static native boolean TProxyStopService();
    public static native boolean TProxyIsRunning();
    public static native long[] TProxyGetStats();
}
