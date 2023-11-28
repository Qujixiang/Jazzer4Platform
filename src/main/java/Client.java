import org.apache.commons.io.FileUtils;
import org.apache.maven.shared.verifier.Verifier;
import org.json.JSONObject;

import java.util.*;
import java.util.regex.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class Client {
    private static final long POLL_INTERVAL_SECONDS = 5L;
    String accessKey = "dynamicCheckJava";
    String secretKey = "c06080599b7fe3a9bd97a4cc7955099d";
    String token;

    String jazzerPath;
    String jazzerJarPath;

    protected final int TASK_START = 1;
    protected final int TASK_FAIL = 0;

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

    public void requestToken() {
        HttpURLConnection connection = null;
        try {
            String url = "https://hust-csdf.liuxx.com/sapi/api/checkTask/authenticate";
            String requestBody = "{\"AccessKey\":\"" + accessKey + "\",\"SecretKey\":\"" + secretKey + "\"}";

            URL apiUrl = new URL(url);
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
            this.token = json.getJSONObject("result").getString("token");

        } catch (IOException e) {
            System.out.println("Error occurred while requesting tasks: " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private void setTestResult(Result result, Task task) {
        HttpURLConnection connection = null;
        try {
            String url = "https://hust-csdf.liuxx.com/sapi/api/checkTask/retunDynamicCheckResult";
            String requestBody = "{\"token\":\"" + token + "\",\"taskid\":\"" + task.taskid + "\",\"toolName\":\"" + "Jazzer" + "\"," + "\"result\":[{\"img_base64\": \"\", \"filename\":\"" + result.fileName + "\",\"line\":" + result.line + ",\"category\":\"" + result.category + "\",\"funName\":\"" + task.targetMethod + "\",\"poc\":\"" + result.poc + result.pocFileName + "\",\"pocFileName\":\"" + result.pocFileName + "\",\"executetime\":" + task.fuzzingTime + "}]}";
//            String requestBody = "{\"token\":\"" + token + "\",\"taskid\":\"" + task.taskid + "\",\"toolName\":\"" + "Jazzer" + "\"," + "\"result\":[{\"img_base64\": \"\", \"filename\":\"JavaTest666.java\",\"line\":" + result.line + ",\"category\":\"" + result.category + "\",\"funName\":\"org.hust.test::main\",\"poc\":\"" + result.poc + "\",\"pocFileName\":\"" + result.pocFileName + "\",\"executetime\":" + -1 + "}]}";

            URL apiUrl = new URL(url);
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
            System.out.println("Error occurred while requesting tasks: " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private void run() {

        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(100);

        Runnable checkForNewTask = () -> {
            requestToken();
            try {
                String SERVER_URL = "https://hust-csdf.liuxx.com/sapi/api/checkTask/getDynamicCheckTask_Java";

                // 发送 HTTP 请求到服务器以检查新任务
                URL apiUrl = new URL(SERVER_URL);
                HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
                String requestBody = "{\"token\":\"" + token + "\",\"codetype\":\"" + "\"}";

                connection = (HttpURLConnection) apiUrl.openConnection();
                connection.setRequestMethod("POST");
                connection.setRequestProperty("Content-Type", "application/json");
                connection.setRequestProperty("Accept", "text/json");
                connection.setDoOutput(true);

                OutputStream outputStream = connection.getOutputStream();
                outputStream.write(requestBody.getBytes());
                outputStream.flush();

                int responseCode = connection.getResponseCode();

                if (responseCode == HttpURLConnection.HTTP_OK) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                    reader.close();
                    JSONObject taskJson = new JSONObject(response.toString());
                    String msg = taskJson.getString("message");
                    if (msg.equals("OK")) {
                        System.out.println("New task detected: " + taskJson);
                        Task task = new Task(taskJson);
                        handleNewTask(task);
                    } else {
                        System.out.println("没有新的检测任务");
                    }
                } else {
                    System.out.println("没有新的检测任务");
//                    20000	成功
//                    50002	鉴权失败，Token无效
//                    10006	token 过期
//                    10007	Token 已加入黑名单
//                    20002	没有检测任务
                }
            } catch (Exception e) {
                System.err.println("Error while checking for new task: " + e.getMessage());
            }
        };

        // 每隔 POLL_INTERVAL_SECONDS 秒执行一次检查
        scheduler.scheduleAtFixedRate(checkForNewTask, 0, POLL_INTERVAL_SECONDS, TimeUnit.SECONDS);
    }

    /*
     * 处理新任务
     * 执行检测时，通过此接口（status=1）通知平台已开始执行任务检测；
     * 检测异常时，通过此接口（status=0）通知平台检测任务执行失败；
     */
    private void setTaskStatus(Task task, int status) {
        HttpURLConnection connection = null;
        try {
            // token	string	必须		通过/checkTask/authentication获得Token，通过此处回传，服务端用于安全验证
            // taskid	number	必须		任务ID
            // status	number	必须		设置检测状态 1开始检测 0检测失败
            // msg	string	必须		检测异常时，需通过此接口返回异常原因


            String url = "https://hust-csdf.liuxx.com/sapi/api/checkTask/setDynamicCheckStatus";
            String requestBody = "{\"token\":\"" + token + "\",\"taskid\":" + task.taskid + ",\"status\":" + status + ",\"msg\":\"" + task.errorMsg + "\"}";

            URL apiUrl = new URL(url);
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
            System.out.println("Error occurred while requesting tasks: " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }


    private void handleNewTask(Task task) {
        setTaskStatus(task, TASK_START);
        downloadProgram(task);
        if (task.status < 0) {
            setTaskStatus(task, TASK_FAIL);
            return;
        }
        checkMaven(task);
        if (task.status < 0) {
            setTaskStatus(task, TASK_FAIL);
            return;
        }
        doFuzzing(task);
        if (task.status < 0) {
            setTaskStatus(task, TASK_FAIL);
            return;
        }
        Result result = new Result(task);
        if (task.status < 0) {
            setTaskStatus(task, TASK_FAIL);
            return;
        }
        setTestResult(result, task);
        cleanUp(task);
    }

    private void cleanUp(Task task) {
        try {
            FileUtils.deleteDirectory(new File(task.targetProgramPath));
        } catch (Exception e) {
            System.out.println("删除文件失败");
        }
    }


    private void doFuzzing(Task task) {
        try {
            FileUtils.copyFile(new File(jazzerPath), new File(task.targetJarPath + "/jazzer"));
            FileUtils.copyFile(new File(jazzerJarPath), new File(task.targetJarPath + "/jazzer_standalone.jar"));

            long startTime = System.currentTimeMillis();
            Process process = Runtime.getRuntime().exec("./jazzer --cp=" + task.projectName + ".jar --autofuzz=" + task.targetMethod, null, new File(task.targetJarPath));
            while (process.isAlive()) {
                Thread.sleep(10);
            }
            long endTime = System.currentTimeMillis();
            task.fuzzingTime = (endTime - startTime) / 1000;


            InputStream inputStream = process.getErrorStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            String line;
            while ((line = reader.readLine()) != null) {
                task.fuzzingResult += line;
            }


        } catch (Exception e) {
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
                task.errorMsg = "git clone failed";
            }
        } catch (Exception e) {
            task.status = -1;
            task.errorMsg = e.toString();
        }
    }

    private void checkMaven(Task task) {
        File taskFile = new File(task.targetProgramPath);
        Map<String, String> env = new HashMap<>();
        env.put("maven.multiModuleProjectDirectory", taskFile.getAbsolutePath());

        try {
            Verifier v = new Verifier(taskFile.getAbsolutePath());
            v.executeGoals(Arrays.asList("clean", "package"), env);
            System.out.println("构建成功！");
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
                System.out.println("编译成功");
            }
        } catch (Exception e) {
            task.status = -2;
            task.errorMsg = "maven build failed";
        }
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

