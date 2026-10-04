package com.psiphon3;

import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class CdnIpScannerActivity extends AppCompatActivity {

    private static final int TCP_CONNECT_TIMEOUT_MS = 2000;
    private static final int TLS_HANDSHAKE_TIMEOUT_MS = 3000;
    private static final int PORT = 443;
    private static final int THREAD_COUNT = 64;

    // Akamai /24 subnets - first five are the exact subnets already hardcoded
    // in TunnelManager.makeCdnFrontingDialOverrides() (known-good in Iran).
    // The rest are neighbors commonly reachable via Akamai anycast.
    private static final String[] SCAN_SUBNETS = {
            "23.215.0.",
            "23.212.250.",
            "23.12.147.",
            "23.73.207.",
            "92.123.102.",
            "23.215.1.",
            "23.212.251.",
            "23.12.146.",
            "23.73.206.",
            "92.123.103.",
            "23.62.0.",
            "23.62.1.",
    };

    private EditText sniInput;
    private Button startBtn;
    private Button stopBtn;
    private Button addBtn;
    private ProgressBar progressBar;
    private TextView statusText;
    private RecyclerView resultsRecycler;

    private ResultAdapter adapter;
    private ExecutorService executor;
    private volatile boolean cancelled = false;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_cdn_ip_scanner);

        sniInput = findViewById(R.id.sniInput);
        startBtn = findViewById(R.id.startButton);
        stopBtn = findViewById(R.id.stopButton);
        addBtn = findViewById(R.id.addToCdnButton);
        progressBar = findViewById(R.id.progressBar);
        statusText = findViewById(R.id.statusText);
        resultsRecycler = findViewById(R.id.resultsRecycler);

        adapter = new ResultAdapter();
        resultsRecycler.setLayoutManager(new LinearLayoutManager(this));
        resultsRecycler.setAdapter(adapter);

        String existingSni = readExistingSni();
        if (TextUtils.isEmpty(existingSni)) {
            existingSni = "pypi.org";
        }
        sniInput.setText(existingSni);

        startBtn.setOnClickListener(v -> startScan());
        stopBtn.setOnClickListener(v -> stopScan());
        addBtn.setOnClickListener(v -> addSelectedToCdn());

        stopBtn.setEnabled(false);
        addBtn.setEnabled(false);
        statusText.setText(R.string.cdn_ip_scanner_idle_hint);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        cancelled = true;
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    private String readExistingSni() {
        SharedPreferences prefs = getSharedPreferences(
                getString(R.string.moreOptionsPreferencesName), MODE_PRIVATE);
        return prefs.getString(getString(R.string.cdnFrontingCustomSniPreference), "");
    }

    private List<String> buildCandidateIps() {
        List<String> ips = new ArrayList<>();
        for (String subnet : SCAN_SUBNETS) {
            for (int i = 1; i <= 254; i++) {
                ips.add(subnet + i);
            }
        }
        return ips;
    }

    private void startScan() {
        final String sni = sniInput.getText().toString().trim();
        if (TextUtils.isEmpty(sni)) {
            Toast.makeText(this, R.string.cdn_ip_scanner_sni_required, Toast.LENGTH_SHORT).show();
            return;
        }

        final List<String> candidates = buildCandidateIps();
        adapter.clear();
        cancelled = false;

        progressBar.setMax(candidates.size());
        progressBar.setProgress(0);
        progressBar.setVisibility(View.VISIBLE);

        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        addBtn.setEnabled(false);
        sniInput.setEnabled(false);

        final int total = candidates.size();
        statusText.setText(getString(R.string.cdn_ip_scanner_progress, 0, total, 0));

        executor = Executors.newFixedThreadPool(THREAD_COUNT);
        final ExecutorCompletionService<Result> ecs =
                new ExecutorCompletionService<>(executor);

        for (String ip : candidates) {
            ecs.submit(new ScanTask(ip, sni));
        }

        new Thread(() -> {
            int done = 0;
            for (int i = 0; i < total; i++) {
                if (cancelled) break;
                try {
                    Future<Result> f = ecs.take();
                    final Result r = f.get();
                    if (r != null && r.success) {
                        uiHandler.post(() -> {
                            if (cancelled) return;
                            adapter.addResult(r);
                            addBtn.setEnabled(adapter.getItemCount() > 0);
                        });
                    }
                } catch (Exception ignored) {
                }
                done++;
                final int doneNow = done;
                uiHandler.post(() -> {
                    if (cancelled) return;
                    progressBar.setProgress(doneNow);
                    statusText.setText(getString(R.string.cdn_ip_scanner_progress,
                            doneNow, total, adapter.getItemCount()));
                });
            }

            uiHandler.post(() -> {
                if (cancelled) return;
                finishScan();
            });
        }).start();
    }

    private void stopScan() {
        cancelled = true;
        if (executor != null) {
            executor.shutdownNow();
        }
        finishScan();
    }

    private void finishScan() {
        progressBar.setVisibility(View.GONE);
        startBtn.setEnabled(true);
        stopBtn.setEnabled(false);
        sniInput.setEnabled(true);
        addBtn.setEnabled(adapter.getItemCount() > 0);

        int found = adapter.getItemCount();
        if (found == 0) {
            statusText.setText(R.string.cdn_ip_scanner_no_results);
        } else {
            statusText.setText(getString(R.string.cdn_ip_scanner_done, found));
        }
    }

    private void addSelectedToCdn() {
        List<Result> selected = adapter.getSelectedResults();
        if (selected.isEmpty()) {
            Toast.makeText(this, R.string.cdn_ip_scanner_select_at_least_one, Toast.LENGTH_SHORT).show();
            return;
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < selected.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(selected.get(i).ip);
        }
        String newIpList = sb.toString();

        String usedSni = sniInput.getText().toString().trim();

        // Write ONLY to SharedPreferences. When the user backs out to
        // OptionsTabFragment, moreSettingsRestartRequired() will detect the
        // change vs. the tray preferences and trigger a tunnel restart.
        SharedPreferences prefs = getSharedPreferences(
                getString(R.string.moreOptionsPreferencesName), MODE_PRIVATE);
        prefs.edit()
                .putString(getString(R.string.cdnFrontingCustomIpListPreference), newIpList)
                .putString(getString(R.string.cdnFrontingCustomSniPreference), usedSni)
                .apply();

        Toast.makeText(this,
                getString(R.string.cdn_ip_scanner_added_success, selected.size()),
                Toast.LENGTH_LONG).show();

        finish();
    }

    // ---- Scan task ----

    private class ScanTask implements Callable<Result> {
        private final String ip;
        private final String sni;

        ScanTask(String ip, String sni) {
            this.ip = ip;
            this.sni = sni;
        }

        @Override
        public Result call() {
            if (cancelled) return null;
            long start = System.currentTimeMillis();

            try (Socket rawSocket = new Socket()) {
                rawSocket.connect(new InetSocketAddress(ip, PORT), TCP_CONNECT_TIMEOUT_MS);

                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                try (SSLSocket sslSocket = (SSLSocket) factory.createSocket(
                        rawSocket, sni, PORT, true)) {

                    // Set SNI explicitly on API 24+ (older APIs set it via createSocket host param)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        SSLParameters params = sslSocket.getSSLParameters();
                        params.setServerNames(
                                Collections.singletonList(new SNIHostName(sni)));
                        sslSocket.setSSLParameters(params);
                    }

                    sslSocket.setSoTimeout(TLS_HANDSHAKE_TIMEOUT_MS);
                    sslSocket.startHandshake();

                    long elapsed = System.currentTimeMillis() - start;
                    if (cancelled) return null;
                    return new Result(ip, elapsed, sni, true);
                }
            } catch (Exception e) {
                // Any failure (timeout, refused, TLS handshake fail) is silently dropped
                return null;
            }
        }
    }

    // ---- Result model ----

    public static class Result {
        final String ip;
        final long latencyMs;
        final String sni;
        final boolean success;
        boolean selected = false;

        Result(String ip, long latencyMs, String sni, boolean success) {
            this.ip = ip;
            this.latencyMs = latencyMs;
            this.sni = sni;
            this.success = success;
        }
    }

    // ---- Adapter ----

    private class ResultAdapter extends RecyclerView.Adapter<ResultViewHolder> {
        private final List<Result> results = new ArrayList<>();

        void clear() {
            results.clear();
            notifyDataSetChanged();
        }

        void addResult(Result r) {
            int idx = 0;
            while (idx < results.size() && results.get(idx).latencyMs <= r.latencyMs) {
                idx++;
            }
            results.add(idx, r);
            notifyItemInserted(idx);
        }

        boolean hasSelection() {
            for (Result r : results) if (r.selected) return true;
            return false;
        }

        List<Result> getSelectedResults() {
            List<Result> sel = new ArrayList<>();
            for (Result r : results) if (r.selected) sel.add(r);
            return sel;
        }

        @NonNull
        @Override
        public ResultViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_cdn_ip_result, parent, false);
            return new ResultViewHolder(v);
        }

        @Override
        public void onBindViewHolder(@NonNull ResultViewHolder h, int position) {
            Result r = results.get(position);
            h.ipText.setText(r.ip);
            h.latencyText.setText(h.itemView.getContext()
                    .getString(R.string.cdn_ip_scanner_time_format, r.latencyMs));
            h.checkBox.setOnCheckedChangeListener(null);
            h.checkBox.setChecked(r.selected);
            h.checkBox.setOnCheckedChangeListener((v, checked) -> {
                r.selected = checked;
                addBtn.setEnabled(hasSelection());
            });
        }

        @Override
        public int getItemCount() {
            return results.size();
        }
    }

    static class ResultViewHolder extends RecyclerView.ViewHolder {
        final TextView ipText;
        final TextView latencyText;
        final CheckBox checkBox;

        ResultViewHolder(@NonNull View itemView) {
            super(itemView);
            ipText = itemView.findViewById(R.id.resultIp);
            latencyText = itemView.findViewById(R.id.resultLatency);
            checkBox = itemView.findViewById(R.id.resultCheckbox);
        }
    }
}