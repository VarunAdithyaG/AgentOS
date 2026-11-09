#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

#define MAX_PROCESSES 4096
#define TOP_COUNT 5

struct cpu_times { unsigned long long total, idle; };
struct process_sample {
	int pid;
	unsigned long long ticks, delta;
	char app[64];
};

static int read_cpu(struct cpu_times *sample)
{
	FILE *file = fopen("/proc/stat", "r");
	unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
	if (!file || fscanf(file, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
		&user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal) != 8) {
		if (file) fclose(file);
		return -1;
	}
	fclose(file);
	sample->idle = idle + iowait;
	sample->total = user + nice + system + idle + iowait + irq + softirq + steal;
	return 0;
}

static double memory_percent(void)
{
	FILE *file = fopen("/proc/meminfo", "r");
	char key[64];
	unsigned long long value, total = 0, available = 0;
	if (!file) return -1;
	while (fscanf(file, "%63s %llu kB", key, &value) == 2) {
		if (!strcmp(key, "MemTotal:")) total = value;
		if (!strcmp(key, "MemAvailable:")) available = value;
	}
	fclose(file);
	return total ? 100.0 * (total - available) / total : -1;
}

static double disk_percent(void)
{
	struct statvfs fs;
	if (statvfs("/", &fs) || !fs.f_blocks) return -1;
	return 100.0 * (fs.f_blocks - fs.f_bfree) / fs.f_blocks;
}

/* Most AMD and Intel DRM drivers expose this portable-in-practice busy value. */
static double gpu_percent(void)
{
	DIR *dir = opendir("/sys/class/drm");
	struct dirent *entry;
	char path[PATH_MAX];
	FILE *file;
	double result = -1;
	if (!dir) return -1;
	while ((entry = readdir(dir))) {
		if (strncmp(entry->d_name, "card", 4) || strchr(entry->d_name, '-'))
			continue;
		snprintf(path, sizeof(path), "/sys/class/drm/%s/device/gpu_busy_percent",
			 entry->d_name);
		file = fopen(path, "r");
		if (file && fscanf(file, "%lf", &result) == 1) {
			fclose(file);
			break;
		}
		if (file) fclose(file);
	}
	closedir(dir);
	return result;
}

static unsigned long long process_ticks(int pid)
{
	char path[64], line[1024], *rest, *save, *token;
	FILE *file;
	int field = 0;
	unsigned long long user = 0, system = 0;
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	file = fopen(path, "r");
	if (!file || !fgets(line, sizeof(line), file)) {
		if (file) fclose(file);
		return 0;
	}
	fclose(file);
	rest = strrchr(line, ')');
	if (!rest || !rest[2]) return 0;
	for (token = strtok_r(rest + 2, " ", &save); token;
	     token = strtok_r(NULL, " ", &save), field++) {
		if (field == 11) user = strtoull(token, NULL, 10);
		if (field == 12) { system = strtoull(token, NULL, 10); break; }
	}
	return user + system;
}

static void process_name(int pid, char *name, size_t size)
{
	char path[64];
	FILE *file;
	snprintf(path, sizeof(path), "/proc/%d/comm", pid);
	file = fopen(path, "r");
	if (!file || !fgets(name, size, file)) {
		if (file) fclose(file);
		snprintf(name, size, "unknown");
		return;
	}
	fclose(file);
	name[strcspn(name, "\n")] = '\0';
}

static size_t sample_processes(struct process_sample *samples)
{
	DIR *dir = opendir("/proc");
	struct dirent *entry;
	size_t count = 0;
	if (!dir) return 0;
	while ((entry = readdir(dir)) && count < MAX_PROCESSES) {
		char *end;
		long pid = strtol(entry->d_name, &end, 10);
		if (*entry->d_name == '\0' || *end || pid <= 0 || pid > INT_MAX) continue;
		samples[count].pid = (int)pid;
		samples[count].ticks = process_ticks((int)pid);
		samples[count].delta = 0;
		process_name((int)pid, samples[count].app, sizeof(samples[count].app));
		count++;
	}
	closedir(dir);
	return count;
}

static unsigned long long previous_ticks(const struct process_sample *previous,
					 size_t count, int pid)
{
	size_t index;
	for (index = 0; index < count; index++)
		if (previous[index].pid == pid) return previous[index].ticks;
	return 0;
}

static int compare_processes(const void *left, const void *right)
{
	const struct process_sample *a = left, *b = right;
	return (b->delta > a->delta) - (b->delta < a->delta);
}

static void append_csv(const char *path, const char *timestamp, double cpu,
		double gpu, double memory, double disk,
		const struct process_sample *processes, size_t count)
{
	FILE *file = fopen(path, "a+");
	size_t index, shown;
	long length;
	if (!file) {
		fprintf(stderr, "Cannot append to CSV file %s: %s\n", path, strerror(errno));
		return;
	}
	fseek(file, 0, SEEK_END);
	length = ftell(file);
	if (length == 0)
		fprintf(file, "timestamp,cpu_percent,gpu_percent,memory_percent,disk_percent,top_pids,top_apps\n");
	fprintf(file, "%s,%.1f,", timestamp, cpu);
	if (gpu < 0) fprintf(file, "N/A,"); else fprintf(file, "%.1f,", gpu);
	fprintf(file, "%.1f,%.1f,\"", memory, disk);
	shown = count < TOP_COUNT ? count : TOP_COUNT;
	for (index = 0; index < shown; index++)
		fprintf(file, "%s%d", index ? ";" : "", processes[index].pid);
	fprintf(file, "\",\"");
	for (index = 0; index < shown; index++)
		fprintf(file, "%s%s", index ? ";" : "", processes[index].app);
	fprintf(file, "\"\n");
	fclose(file);
}

static void print_line(const struct cpu_times *before,
		const struct process_sample *previous, size_t previous_count,
		const char *csv_path)
{
	struct cpu_times after;
	struct process_sample current[MAX_PROCESSES];
	size_t count, index, shown;
	double cpu, gpu, memory, disk;
	time_t now = time(NULL);
	char timestamp[32];
	struct tm local;
	if (read_cpu(&after)) return;
	count = sample_processes(current);
	for (index = 0; index < count; index++) {
		unsigned long long old = previous_ticks(previous, previous_count, current[index].pid);
		current[index].delta = current[index].ticks >= old ? current[index].ticks - old : 0;
	}
	qsort(current, count, sizeof(*current), compare_processes);
	cpu = after.total > before->total ? 100.0 * ((after.total - before->total) -
		(after.idle - before->idle)) / (after.total - before->total) : 0;
	memory = memory_percent(); disk = disk_percent(); gpu = gpu_percent();
	localtime_r(&now, &local);
	strftime(timestamp, sizeof(timestamp), "%F %T", &local);
	printf("%s [✓] CPU: %.1f%%  GPU: ", timestamp, cpu);
	if (gpu < 0) printf("N/A"); else printf("%.1f%%", gpu);
	printf("  Mem: %.1f%%  Disk: %.1f%%  Top PIDs: ", memory, disk);
	shown = count < TOP_COUNT ? count : TOP_COUNT;
	for (index = 0; index < shown; index++)
		printf("%s%d", index ? "," : "", current[index].pid);
	if (!shown) printf("N/A");
	printf("  Top Apps: ");
	for (index = 0; index < shown; index++)
		printf("%s%s", index ? "," : "", current[index].app);
	if (!shown) printf("N/A");
	putchar('\n');
	append_csv(csv_path, timestamp, cpu, gpu, memory, disk, current, count);
	fflush(stdout);
}

int main(int argc, char **argv)
{
	long interval = 15;
	char *end;
	char csv_path[PATH_MAX];
	char *separator;
	ssize_t executable_length;
	struct cpu_times before;
	struct process_sample previous[MAX_PROCESSES];
	size_t previous_count;

	/* Keep the default CSV beside this executable, regardless of the launch cwd. */
	executable_length = readlink("/proc/self/exe", csv_path, sizeof(csv_path) - 1);
	if (executable_length < 0) {
		snprintf(csv_path, sizeof(csv_path), "system_metrics.csv");
	} else {
		csv_path[executable_length] = '\0';
		separator = strrchr(csv_path, '/');
		if (!separator) {
			snprintf(csv_path, sizeof(csv_path), "system_metrics.csv");
		} else {
			snprintf(separator + 1, sizeof(csv_path) - (size_t)(separator + 1 - csv_path),
				 "system_metrics.csv");
		}
	}
	if ((argc == 3 || argc == 5) && !strcmp(argv[1], "--watch")) {
		interval = strtol(argv[2], &end, 10);
		if (*argv[2] == '\0' || *end || interval <= 0) goto usage;
		if (argc == 5 && !strcmp(argv[3], "--csv") && argv[4][0])
			snprintf(csv_path, sizeof(csv_path), "%s", argv[4]);
		else if (argc == 5) goto usage;
	} else if (argc != 1) goto usage;
	if (read_cpu(&before)) { perror("/proc/stat"); return EXIT_FAILURE; }
	previous_count = sample_processes(previous);
	for (;;) {
		sleep((unsigned int)interval);
		print_line(&before, previous, previous_count, csv_path);
		if (read_cpu(&before)) break;
		previous_count = sample_processes(previous);
	}
	return EXIT_FAILURE;
usage:
	fprintf(stderr, "Usage: %s [--watch seconds [--csv file.csv]]\n", argv[0]);
	return EXIT_FAILURE;
}
