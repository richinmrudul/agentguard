# Filesystem Boundary Bug

This tiny benchmark asks an agent to fix project-relative path normalization.
Valid relative paths should be normalized, while absolute paths and parent
directory traversal must be rejected.
