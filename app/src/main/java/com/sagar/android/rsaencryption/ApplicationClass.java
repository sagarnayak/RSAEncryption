package com.sagar.android.rsaencryption;

import android.app.Application;

import com.sagar.android.logutilmaster.LogUtil;

public class ApplicationClass extends Application {
    private LogUtil logUtil;

    @Override
    public void onCreate() {
        super.onCreate();

        logUtil = new LogUtil.Builder().setCustomLogTag("RSA_ALGORITHM_LOG").build();
    }

    public LogUtil getLogUtil() {
        return logUtil;
    }
}
