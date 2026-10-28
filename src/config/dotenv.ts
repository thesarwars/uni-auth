/**
 * Loads .env, if there is one, before anything reads process.env.
 *
 * Import this first - env.ts does, and so does every script that talks to the database.
 *
 * dotenv does not overwrite a variable that is already set, which is the precedence this
 * project wants: in Docker, in CI and in production the environment is supplied by the
 * platform and there is no file, so this call does nothing. The file is a developer
 * convenience and never a source of truth.
 *
 * The path is resolved from this module rather than from process.cwd(), so a script run from
 * a subdirectory still finds it.
 */
import { config } from 'dotenv';
import { resolve } from 'node:path';

config({ path: resolve(__dirname, '..', '..', '.env'), quiet: true });
