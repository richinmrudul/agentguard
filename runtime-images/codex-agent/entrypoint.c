#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int missing(const char *name) {
    fprintf(stderr, "%s is required\n", name);
    return 64;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        char *version_argv[] = {"codex", "--version", NULL};
        execv("/opt/codex/bin/codex", version_argv);
        fprintf(stderr, "failed to exec codex --version: %s\n", strerror(errno));
        return 127;
    }

    const char *api_key = getenv("CODEX_API_KEY");
    if (api_key == NULL || api_key[0] == '\0') {
        return missing("CODEX_API_KEY");
    }
    const char *model = getenv("CODEX_MODEL");
    if (model == NULL || model[0] == '\0') {
        return missing("CODEX_MODEL");
    }

    unsetenv("OPENAI_API_KEY");
    unsetenv("NPM_TOKEN");
    unsetenv("GH_TOKEN");
    unsetenv("GITHUB_TOKEN");

    int extra = argc > 1 ? argc - 1 : 0;
    int fixed = 6;
    char **next = calloc((size_t)(fixed + extra + 1), sizeof(char *));
    if (next == NULL) {
        fprintf(stderr, "failed to allocate argv\n");
        return 70;
    }
    int index = 0;
    next[index++] = "codex";
    next[index++] = "exec";
    next[index++] = "--model";
    next[index++] = (char *)model;
    next[index++] = "--json";
    next[index++] = "--skip-git-repo-check";
    for (int i = 1; i < argc; i++) {
        next[index++] = argv[i];
    }
    next[index] = NULL;

    execv("/opt/codex/bin/codex", next);
    fprintf(stderr, "failed to exec codex: %s\n", strerror(errno));
    return 127;
}
