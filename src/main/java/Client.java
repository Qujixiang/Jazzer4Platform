import org.apache.commons.io.FileUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.concurrent.ExecutorService;
import java.util.regex.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class Client {
    private static final long POLL_INTERVAL_SECONDS = 5L;
    String jazzerPath;
    String jazzerJarPath;

    protected final int TASK_START = 1;
    protected final int TASK_FAIL = 0;
    String accessKey = "dynamicCheck";
    String secretKey = "c06080599b7fe3a9bd97a4cc7955099d";
    String url = System.getenv("API_SERVICE_URL");
    String token = null;

    public Client() {
        if (System.getProperty("os.name").toLowerCase().contains("linux")) {
            jazzerPath = "jazzer_linux";
            jazzerJarPath = "jazzer_standalone_linux.jar";
        } else if (System.getProperty("os.name").toLowerCase().contains("mac")) {
            jazzerPath = "jazzer_macos";
            jazzerJarPath = "jazzer_standalone_macos.jar";
        }
    }

    public static void main(String[] args) {
        Client client = new Client();
        client.run();
    }

    private void setTestResult(Result result, Task task) {
        HttpURLConnection connection = null;
        try {
            JSONObject requestJson = new JSONObject();
            requestJson.put("token", token);
            requestJson.put("taskid", task.taskid);
            requestJson.put("toolName", "Jazzer");
            requestJson.put("result", new JSONObject[]{new JSONObject("{\"img_base64\": \"\", \"filename\":\"" + result.fileName + "\",\"line\":" + result.line + ",\"category\":\"" + result.category + "\",\"funName\":\"" + task.targetMethod + "\",\"poc\":\"" + result.poc + result.pocFileName + "\",\"pocFileName\":\"" + result.pocFileName + "\",\"executetime\":" + task.fuzzingTime + "}")});
            String requestBody = requestJson.toString();

            // 返回检测结果
            URL apiUrl = new URL(url + "/api/checkTask/retunDynamicCheckResult");
            connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "text/json");
            connection.setDoOutput(true);

            OutputStream outputStream = connection.getOutputStream();
            outputStream.write(requestBody.getBytes());
            outputStream.flush();

            int responseCode = connection.getResponseCode();
            BufferedReader reader;
            if (responseCode == HttpURLConnection.HTTP_OK) {
                reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            } else {
                reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            }

            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            JSONObject json = new JSONObject(response.toString());
            System.out.println(json);
        } catch (IOException e) {
            handleException(e, "setTestResult failed");
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * 接口鉴权
     *
     * @param apiURL 接口地址
     * @param accessKey 访问秘钥
     * @param secretKey 访问秘钥
     * @return token，失败返回null
     */
    public String authenticate(String apiURL, String accessKey, String secretKey) {
        HttpURLConnection connection = null;
        try {
            JSONObject requestJson = new JSONObject();
            requestJson.put("AccessKey", accessKey);
            requestJson.put("SecretKey", secretKey);
            String requestBody = requestJson.toString();

            URL apiUrl = new URL(apiURL);
            connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "text/json");
            connection.setDoOutput(true);

            OutputStream outputStream = connection.getOutputStream();
            outputStream.write(requestBody.getBytes());
            outputStream.flush();

            int responseCode = connection.getResponseCode();
            BufferedReader reader;
            if (responseCode == HttpURLConnection.HTTP_OK) {
                reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            } else {
                reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            }

            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            JSONObject json = new JSONObject(response.toString());
            JSONObject result = json.getJSONObject("result");
            return result.getString("token");
        } catch (IOException e) {
            handleException(e, "authenticate failed");
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return null;
    }

    /**
     * 获取检测任务
     *
     * @param apiURL 接口地址
     * @param token token
     * @return 任务， 失败返回null
     */
    public Task getCheckTask(String apiURL, String token) {
        HttpURLConnection connection = null;
        try {
            JSONObject requestJson = new JSONObject();
            requestJson.put("token", token);
            String requestBody = requestJson.toString();

            URL apiUrl = new URL(apiURL);
            connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "text/json");
            connection.setDoOutput(true);

            OutputStream outputStream = connection.getOutputStream();
            outputStream.write(requestBody.getBytes());
            outputStream.flush();

            int responseCode = connection.getResponseCode();
            BufferedReader reader;
            if (responseCode == HttpURLConnection.HTTP_OK) {
                reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            } else {
                reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            }

            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            JSONObject taskJson = new JSONObject(response.toString());
            String msg = taskJson.getString("message");
            if (msg.equals("OK")) {
                return new Task(taskJson);
            }
        } catch (IOException e) {
            handleException(e, "getCheckTask failed");
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return null;
    }

    private void run() {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(100);
        final ExecutorService taskExecutor = Executors.newCachedThreadPool();

        Runnable checkForNewTask = () -> {
            // 鉴权
            token = authenticate(url + "/api/checkTask/authenticate", accessKey, secretKey);
            if (token == null) {
                throw new RuntimeException("接口鉴权失败");
            }

            // 获取任务
            Task task = getCheckTask(url + "/api/checkTask/getDynamicCheckTask_Java", token);
            if (task == null) {
                System.out.println("没有新的检测任务");
                return;
            }

            // 处理任务
            taskExecutor.submit(() -> {
                handleNewTask(task);
            });
        };

        // 每隔 POLL_INTERVAL_SECONDS 秒执行一次检查
        scheduler.scheduleAtFixedRate(checkForNewTask, 0, POLL_INTERVAL_SECONDS, TimeUnit.SECONDS);
    }

    /**
     * 设置任务状态
     *
     * @param task 任务
     * @param status 状态，1-开始检测，0-检测失败
     */
    private void setTaskStatus(Task task, int status) {
        HttpURLConnection connection = null;
        try {
            JSONObject requestJson = new JSONObject();
            requestJson.put("token", token);
            requestJson.put("taskid", task.taskid);
            requestJson.put("status", status);
            requestJson.put("msg", task.errorMsg);
            String requestBody = requestJson.toString();

            URL apiUrl = new URL(url + "/api/checkTask/setDynamicCheckStatus");
            connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "text/json");
            connection.setDoOutput(true);

            OutputStream outputStream = connection.getOutputStream();
            outputStream.write(requestBody.getBytes());
            outputStream.flush();

            int responseCode = connection.getResponseCode();
            BufferedReader reader;
            if (responseCode == HttpURLConnection.HTTP_OK) {
                reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            } else {
                reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            }

            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            System.out.println("response: " + response);

        } catch (IOException e) {
            handleException(e, "setTaskStatus failed");
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * 获取动态检测是否停止
     *
     * @param task 任务
     * @return 1-停止
     */
    private int getDynamicCheckStop(Task task) {
        HttpURLConnection connection = null;
        int retValue = 1;
        try {
            JSONObject requestJson = new JSONObject();
            requestJson.put("token", token);
            requestJson.put("taskid", task.taskid);
            String requestBody = requestJson.toString();

            URL apiUrl = new URL(url + "/api/checkTask/getDynamicCheckStop");
            connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "text/json");
            connection.setDoOutput(true);

            OutputStream outputStream = connection.getOutputStream();
            outputStream.write(requestBody.getBytes());
            outputStream.flush();

            int responseCode = connection.getResponseCode();
            BufferedReader reader;
            if (responseCode == HttpURLConnection.HTTP_OK) {
                reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            } else {
                reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            }
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            JSONObject taskJson = new JSONObject(response.toString());
            JSONObject result = taskJson.getJSONObject("result");
            retValue = result.getInt("stop");
        } catch (IOException e) {
            handleException(e, "getDynamicCheckStop failed");
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return retValue;
    }

    private void handleNewTask(Task task) {
        setTaskStatus(task, TASK_START);
        downloadProgram(task);
        if (task.status < 0) {
            setTaskStatus(task, TASK_FAIL);
            cleanUp(task);
            return;
        }
        checkMaven(task);
        if (task.status < 0) {
            setTaskStatus(task, TASK_FAIL);
            cleanUp(task);
            return;
        }
        doFuzzing(task);
        if (task.status < 0) {
            setTaskStatus(task, TASK_FAIL);
            cleanUp(task);
            return;
        }
        Result result = new Result(task);
        if (task.status < 0) {
            setTaskStatus(task, TASK_FAIL);
            cleanUp(task);
        }
        setTestResult(result, task);
    }

    private void cleanUp(Task task) {
        try {
            FileUtils.deleteDirectory(new File(task.targetProgramPath));
        } catch (Exception e) {
            handleException(e, "clean up failed");
        }
    }

    private void doFuzzing(Task task) {
        try {
            FileUtils.copyFile(new File(jazzerPath), new File(task.targetJarPath + "/jazzer"));
            FileUtils.copyFile(new File(jazzerJarPath), new File(task.targetJarPath + "/jazzer_standalone.jar"));

            long startTime = System.currentTimeMillis();
            Process process = Runtime.getRuntime().exec("./jazzer --cp=" + task.projectName + ".jar --autofuzz=" + task.targetMethod, null, new File(task.targetJarPath));
            while (process.isAlive()) {
                Thread.sleep(1000);
                if (getDynamicCheckStop(task) == 1) {
                    process.destroy();
                    break;
                }
            }
            long endTime = System.currentTimeMillis();
            task.fuzzingTime = (endTime - startTime) / 1000;

            InputStream inputStream = process.getErrorStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            String line;
            while ((line = reader.readLine()) != null) {
                task.fuzzingResult += line;
            }
            System.out.println(task.fuzzingResult);

        } catch (Exception e) {
            handleException(e, "fuzzing failed");
            task.status = -3;
            task.errorMsg = e.toString();
        }
    }

    private void downloadProgram(Task task) {
        String url = task.cloneUrl;
        String tag = task.cloneTag;
        String targetProgramPath = task.targetProgramPath;
        String cmd = "git clone --branch " + tag + " " + url + " " + targetProgramPath;
        try {
            Process process = Runtime.getRuntime().exec(cmd);
            while (process.isAlive()) {
                Thread.sleep(100);
            }
            if (process.exitValue() != 0) {
                task.status = -1;
//                task.errorMsg = "git clone failed";
                task.errorMsg = cmd;
            } else {
                System.out.println("git clone success");
            }
        } catch (Exception e) {
            handleException(e, "git clone failed");
            task.status = -1;
            task.errorMsg = e.toString();
        }
    }

    private void checkMaven(Task task) {
        File taskFile = new File(task.targetProgramPath);
        String cmd = "mvn clean package";
        try {
            System.out.println("开始编译: " + task.targetProgramPath);
            Process process = Runtime.getRuntime().exec(cmd, null, taskFile);
            while (process.isAlive()) {
                Thread.sleep(100);
            }
            System.out.println("编译成功！");
            File file = new File(task.targetProgramPath + "target/");
            File[] files = file.listFiles();
            if (files != null) {
                for (File f : files) {
                    if (f.getName().endsWith(".jar")) {
                        FileUtils.moveFile(f, new File(task.targetProgramPath + "target/" + task.projectName + ".jar"));
                        task.targetJarPath = f.getParent();
                        task.status = 1;
                        break;
                    }
                }
            }
        } catch (Exception e) {
            handleException(e, "编译失败: " + task.targetProgramPath);
            task.status = -2;
            task.errorMsg = e.toString();
        }
    }

    private void handleException(Exception e, String message) {
        System.err.println("----------------- Exception -----------------");
        System.err.println(message);
        System.err.println(e.getMessage());
        e.printStackTrace();
        System.err.println("----------------------------------------------");
    }
}


class Result {
    String fileName = "";
    int line = -1;
    String category = "";
    String methodName = "";
    String poc = "";
    String pocFileName = "";
    Task task;

    public Result(Task task) {
        this.task = task;
        analyzeOutput(task.fuzzingResult);
    }

    private static void executeCommand(String command, String directory) throws InterruptedException, IOException {
        Process process = Runtime.getRuntime().exec(command, null, new File(directory));
        while (process.isAlive()) {
            Thread.sleep(100);
        }
    }

    private void analyzeOutput(String output) {
        if (output.isEmpty()) return;
//        output = "INFO: Loaded 156 hooks from com.code_intelligence.jazzer.runtime.TraceCmpHooks\n" + "INFO: Loaded 4 hooks from com.code_intelligence.jazzer.runtime.TraceDivHooks\n" + "INFO: Loaded 2 hooks from com.code_intelligence.jazzer.runtime.TraceIndirHooks\n" + "INFO: Loaded 4 hooks from com.code_intelligence.jazzer.runtime.NativeLibHooks\n" + "INFO: Loaded 5 hooks from com.code_intelligence.jazzer.sanitizers.Deserialization\n" + "INFO: Loaded 5 hooks from com.code_intelligence.jazzer.sanitizers.ExpressionLanguageInjection\n" + "INFO: Loaded 70 hooks from com.code_intelligence.jazzer.sanitizers.LdapInjection\n" + "INFO: Loaded 46 hooks from com.code_intelligence.jazzer.sanitizers.NamingContextLookup\n" + "INFO: Loaded 1 hooks from com.code_intelligence.jazzer.sanitizers.OsCommandInjection\n" + "INFO: Loaded 52 hooks from com.code_intelligence.jazzer.sanitizers.ReflectiveCall\n" + "INFO: Loaded 8 hooks from com.code_intelligence.jazzer.sanitizers.RegexInjection\n" + "INFO: Loaded 16 hooks from com.code_intelligence.jazzer.sanitizers.RegexRoadblocks\n" + "INFO: Loaded 2 hooks from com.code_intelligence.jazzer.sanitizers.ServerSideRequestForgery\n" + "INFO: Loaded 19 hooks from com.code_intelligence.jazzer.sanitizers.SqlInjection\n" + "INFO: Loaded 6 hooks from com.code_intelligence.jazzer.sanitizers.XPathInjection\n" + "INFO: Instrumented org.apache.commons.io.input.BoundedInputStream (took 134 ms, size +17%)\n" + "INFO: found LLVMFuzzerCustomMutator (0x7fffc43fb390). Disabling -len_control by default.\n" + "INFO: libFuzzer ignores flags that start with '--'\n" + "INFO: Running with entropic power schedule (0xFF, 100).\n" + "INFO: Seed: 2875124230\n" + "INFO: Loaded 1 modules   (512 inline 8-bit counters): 512 [0xd07970, 0xd07b70), \n" + "INFO: Loaded 1 PC tables (512 PCs): 512 [0xcf5910,0xcf7910), \n" + "INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes\n" + "INFO: A corpus is not provided, starting from an empty corpus\n" + "\n" + "== Java Exception: java.lang.NullPointerException\n" + "        at org.apache.commons.io.input.BoundedInputStream.mark(BoundedInputStream.java:141)\n" + "        at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\n" + "        at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\n" + "        at java.base/jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\n" + "        at java.base/java.lang.reflect.Method.invoke(Method.java:566)\n" + "DEDUP_TOKEN: 73e1904bb4ad5a9e\n" + "== libFuzzer crashing input ==\n" + "MS: 0 ; base unit: 0000000000000000000000000000000000000000\n" + "0xa,\n" + "\\012\n" + "artifact_prefix='./'; Test unit written to ./crash-adc83b19e793491b1c6ea0fd8b46cd9f32e592fc\n" + "Base64: Cg==\n" + "reproducer_path='.'; Java reproducer written to ./Crash_adc83b19e793491b1c6ea0fd8b46cd9f32e592fc.java\n" + "\n" + "\n" + "INFO: To continue fuzzing past this particular finding, rerun with the following additional argument:\n" + "\n" + "    --ignore=73e1904bb4ad5a9e\n" + "\n" + "To ignore all findings of this kind, rerun with the following additional argument:\n" + "\n" + "    --autofuzz_ignore=java.lang.NullPointerException";
        Pattern pattern = Pattern.compile("== Java Exception: (.*?)\\s+at (.*?)\\((.*?)\\.java:(\\d+)\\).*?Java reproducer written to (.*?.java)", Pattern.DOTALL);
        Matcher matcher = pattern.matcher(output);

        if (matcher.find()) {
            this.category = matcher.group(1);
            this.fileName = matcher.group(3) + ".java";
            this.pocFileName = matcher.group(5).replace("./", "");
            this.line = Integer.parseInt(matcher.group(4));
            this.poc = "./target/";
            try {
                executeCommand("git checkout -b task_" + task.taskid, task.targetJarPath);
                executeCommand("git add .", task.targetJarPath);
                executeCommand("git commit -m \"task_" + task.taskid + "\"", task.targetJarPath);
                executeCommand("git push origin task_" + task.taskid, task.targetJarPath);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            task.status = -3;
            task.errorMsg = task.fuzzingResult;
        }
    }
}

class Task {
    int taskid;
    //    String img_base64;
    String projectName;
    String cloneUrl;

    String cloneTag;
    //    String fuzzerType;
    String errorMsg;
    String targetMethod;
    String targetProgramPath;
    String targetJarPath;
    long fuzzingTime = 0;
    String fuzzingResult = "";
    int status = 0;
    // -3: fuzzing error
    // -2: mvn error
    // -1: git error
    // 0: not start
    // 1: start
    // 2: finish


    public Task(JSONObject task) {
        JSONObject result = (JSONObject) task.getJSONArray("result").get(0);
        taskid = result.getInt("taskid");
//        projectName = result.getString("projectName");
        projectName = result.getString("name");
        cloneUrl = result.getString("cloneuri");
        cloneTag = result.getString("clonetag");
        targetMethod = result.getString("targetMethod");
//        targetMethod = result.getString("fuzzerName");
        targetProgramPath = "./FuzzingProgram/" + projectName + System.currentTimeMillis() + "/";
    }

    @Override
    public String toString() {
        return "taskid: " + taskid + "\n" + "projectName: " + projectName + "\n" + "cloneUrl: " + cloneUrl + "\n" + "cloneTag: " + cloneTag + "\n" + "targetMethod: " + targetMethod;
    }
}

