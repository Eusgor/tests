#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>

#include <sys/kcov.h>

#define KCOV_PATH "/dev/kcov"
#define COVER_SIZE (16 << 20)	//maximum size
#define BUF_SIZE (2 << 20)
#define COUNT 16000000
#define COV_FILE "coverage.info"
#define ADDR2LINE "/usr/local/bin/addr2line"
#define KERNEL "/usr/lib/debug/boot/kernel/kernel.debug"
#define KERNDIR "/usr/src/sys"
#define COV_DIR "cov_info"

size_t bufsize = KCOV_ENTRY_SIZE * BUF_SIZE;

typedef struct _cov_point{
	size_t addr;
	size_t count;
} cov_point;

static int compare(const void *p1, const void *p2)
{
	size_t i = *((size_t *)p1);
	size_t j = *((size_t *)p2);

	if (i > j) return (1);
	if (i < j) return (-1);
	return 0;
}

// write to the file
// int wtfile(cov_point *buffer, int nbuf)
// {
// 	int i;
// 	FILE *fd;
// 	fd = fopen("rawfile.log", "w");
// 	if (!fd) 
// 		return 1;
// 	fprintf(fd, "%jx\n", (uintmax_t)buffer[0]);
// 	for (i = 0; i < nbuf - 1; i++) {
// 		if (buffer[i] != buffer[i + 1])
// 			fprintf(fd, "%jx\n", (uintmax_t)buffer[i + 1]);
// 	}
// 	fclose(fd);
// 	return 0;
// }

//write to the buffer
int wtbuffer(char *fname, size_t *cover, cov_point *buffer, int *nbuf)
{
	int i;
	if (*nbuf > (bufsize * 70 / 100)) {
		bufsize *= 2;
		buffer = realloc(buffer, bufsize);
		if (!buffer) 
			return 1;
	}
	size_t size = cover[0] * KCOV_ENTRY_SIZE;
	size_t *dupl = malloc(size);
	if (!dupl) 
		return 1;
	for (int j = 0; j < cover[0]; j++)
		dupl[j] = cover[j + 1];

	//sort
	qsort(dupl, cover[0], KCOV_ENTRY_SIZE, compare);

	//compress
	buffer[*nbuf].addr = dupl[0];
	buffer[*nbuf].count = 1;
	for (i = 0; i < cover[0] - 1; i++) {
		if (dupl[i] != dupl[i + 1]) {
			++(*nbuf);
			buffer[*nbuf].addr = dupl[i + 1];
			buffer[*nbuf].count = 1;
		}
		else
			buffer[*nbuf].count++;
	}
	free(dupl);
	return 0;
}

int main(int argc, char **argv)
{
	int fd, pid, status, nbuf = 0, nl = 0;
	FILE *nmfile, *addrfile;
	size_t *cover; 
	cov_point *buffer;
	char fname[40];
	char command[200];
	char smbl;

	if (argc == 1)
		fprintf(stderr, "usage: kcovtrace program [args...]\n"), exit(1);
	nmfile = fopen(KERNEL, "r");
	if (!nmfile)
		perror("File "KERNEL), exit(1);
	fclose(nmfile);
	nmfile = fopen(KERNDIR, "r");
	if (!nmfile) 
		perror("Directory "KERNDIR), exit(1);
	fclose(nmfile);
		
	fd = open(KCOV_PATH, O_RDWR);
	if (fd == -1)
		perror("open /dev/kcov"), exit(1);

	if (ioctl(fd, KIOSETBUFSIZE, COVER_SIZE))
		perror("ioctl:KIOSETBUFSIZE"), exit(1);
	cover = (size_t*)mmap(NULL, COVER_SIZE * KCOV_ENTRY_SIZE,
			       PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if ((void *)cover == MAP_FAILED)
		perror("mmap"), exit(1);
	pid = fork();
	if (pid < 0)
		perror("fork"), exit(1);
	if (pid == 0) {
		if (ioctl(fd, KIOENABLE, KCOV_MODE_TRACE_PC))
			perror("ioctl:KIOENABLE"), exit(1);
		cover[0] = 0;
		execvp(argv[1], argv + 1);
		perror("execvp");
		exit(255);
	}
	buffer = malloc(bufsize);
	if (!buffer){
		kill(pid, SIGTERM);
		perror("malloc: BUF_SIZE"), exit(1);
	}
	//control the child proccess
	while (waitpid(-1, &status, WNOHANG) != pid) {
		if (cover[0] > COUNT) {
			kill(pid, SIGSTOP);
			if (wtbuffer(fname, cover, buffer, &nbuf)) {
				kill(pid, SIGTERM);
				perror("wtbuffer"), exit(1);
			}
			cover[0] = 0;
			kill(pid, SIGCONT);
		}
	}
	
	if (WEXITSTATUS(status) == 255) {		
		fprintf(stderr, "File %s not found\n", argv[1]);
		exit(1);
	}
	if (wtbuffer(fname, cover, buffer, &nbuf)) {
		perror("wtbuffer"), exit(1);
	}
	if (munmap(cover, COVER_SIZE * KCOV_ENTRY_SIZE))
		perror("munmap"), exit(1);
	if (close(fd))
		perror("close"), exit(1);

	// qsort(buffer, nbuf, sizeof(cov_point), compare);
	// if (wtfile(buffer, nbuf))
	// 	perror("wtfile"), exit(1);
		
	char *env = getenv("KPATH");
	if (!env) {
		printf("---KPATH not found---\n");
		exit(1);
	}
	
	FILE *fdes;
	fdes = fopen(env, "a");
	if (!fdes) 
		return 1;	

	for (int i = 0; i < nbuf; i++) {
		fprintf(fdes, "0x%jx,%ju\n", buffer[i].addr, buffer[i].count);
	}
	fclose(fdes);
	free(buffer);

	return WEXITSTATUS(status);
}
