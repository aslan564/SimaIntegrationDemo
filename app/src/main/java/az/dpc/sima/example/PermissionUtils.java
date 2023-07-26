package az.dpc.sima.example;

import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

public class PermissionUtils {
    public static void startPermissionRequest(Context context, Activity activity, String permission, PermissionResultListener onComplete) {

        if (ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED) {
            onComplete.onPermissionResult(true, false, permission);
        } else
            onComplete.onPermissionResult(false, ActivityCompat.shouldShowRequestPermissionRationale(activity, permission), permission);
    }

    public interface PermissionResultListener {
        void onPermissionResult(boolean isItAllowed, boolean isShouldShowRequestPermission, String permission);
    }
}
