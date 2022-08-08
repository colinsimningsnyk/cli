import { Ora } from 'ora';
import { EOL } from 'os';
import { convertEngineToJsonResults } from './json';
import { TestOutput } from './scan/results';

import { TestCommandResult } from '../../../../cli/commands/types';
import {
  formatIacTestFailures,
  formatIacTestSummary,
  getIacDisplayedIssues,
  IaCTestFailure,
  spinnerSuccessMessage,
} from '../../../formatters/iac-output';
import { formatSnykIacTestTestData } from '../../../formatters/iac-output';
import { jsonStringifyLargeObject } from '../../../json';
import { IacOrgSettings } from '../../../../cli/commands/test/iac/local-execution/types';
import { convertEngineToSarifResults } from './sarif';
import { CustomError, FormattedCustomError } from '../../../errors';
import { SnykIacTestError } from './errors';

export function buildOutput({
  scanResult,
  testSpinner,
  projectName,
  orgSettings,
  options,
}: {
  scanResult: TestOutput;
  testSpinner?: Ora;
  projectName: string;
  orgSettings: IacOrgSettings;
  options: any;
}): TestCommandResult {
  if (scanResult.results) {
    testSpinner?.succeed(spinnerSuccessMessage);
  } else {
    testSpinner?.stop();
  }

  const { responseData, jsonData, sarifData } = buildTestCommandResultData({
    scanResult,
    projectName,
    orgSettings,
    options,
  });

  if (options.json || options.sarif) {
    return TestCommandResult.createJsonTestCommandResult(
      responseData,
      jsonData,
      sarifData,
    );
  }

  return TestCommandResult.createHumanReadableTestCommandResult(
    responseData,
    jsonData,
    sarifData,
  );
}

function buildTestCommandResultData({
  scanResult,
  projectName,
  orgSettings,
  options,
}: {
  scanResult: TestOutput;
  projectName: string;
  orgSettings: IacOrgSettings;
  options: any;
}) {
  const jsonData = jsonStringifyLargeObject(
    convertEngineToJsonResults({
      results: scanResult,
      projectName,
      orgSettings,
    }),
  );

  const sarifData = jsonStringifyLargeObject(
    convertEngineToSarifResults(scanResult),
  );

  let responseData: string;
  if (options.json) {
    responseData = jsonData;
  } else if (options.sarif) {
    responseData = sarifData;
  } else {
    responseData = buildTextOutput({ scanResult, projectName, orgSettings });
  }

  const isFoundIssues = !!scanResult.results?.vulnerabilities?.length;
  if (isFoundIssues) {
    throw new FoundIssuesError({
      response: responseData,
      json: jsonData,
      sarif: sarifData,
    });
  }

  const isPartialSuccess =
    scanResult.results?.resources?.length || !scanResult.errors?.length;
  if (!isPartialSuccess) {
    if (options.json || options.sarif) {
      throw new NoSuccessfulScansJsonAndSarifError(
        { response: responseData, json: jsonData, sarif: sarifData },
        scanResult.errors!,
        !options.sarif,
      );
    } else {
      throw new NoSuccessfulScansTextError(responseData, scanResult.errors!);
    }
  }

  return { responseData, jsonData, sarifData };
}

const SEPARATOR = '\n-------------------------------------------------------\n';

function buildTextOutput({
  scanResult,
  projectName,
  orgSettings,
}: {
  scanResult: TestOutput;
  projectName: string;
  orgSettings: IacOrgSettings;
}): string {
  let response = '';

  const testData = formatSnykIacTestTestData(
    scanResult.results,
    projectName,
    orgSettings.meta.org,
  );

  response +=
    EOL +
    getIacDisplayedIssues(testData.resultsBySeverity, {
      shouldShowLineNumbers: true,
    });

  if (scanResult.errors) {
    const testFailures: IaCTestFailure[] = scanResult.errors.map((error) => ({
      filePath: error.fields.path,
      failureReason: error.userMessage,
    }));

    response += EOL.repeat(2) + formatIacTestFailures(testFailures);
  }

  response += EOL;
  response += SEPARATOR;
  response += EOL;
  response += formatIacTestSummary(testData);
  response += EOL;

  return response;
}

interface ResponseData {
  response: string;
  json: string;
  sarif: string;
}

export class NoSuccessfulScansTextError extends FormattedCustomError {
  constructor(response: string, errors: SnykIacTestError[]) {
    super(
      response,
      formatIacTestFailures(
        errors.map((scanError) => ({
          failureReason: scanError.userMessage,
          filePath: scanError.fields.path,
        })),
      ),
    );

    const firstErr = errors[0];
    this.strCode = firstErr.strCode;
    this.code = firstErr.code;
  }
}

export class NoSuccessfulScansJsonAndSarifError extends CustomError {
  public json: string;
  public jsonStringifiedResults: string;
  public sarifStringifiedResults: string;

  constructor(
    responseData: ResponseData,
    errors: SnykIacTestError[],
    isJson: boolean,
  ) {
    super(responseData.response);

    const firstErr = errors[0];
    this.strCode = firstErr.strCode;
    this.json = responseData.response;
    this.jsonStringifiedResults = responseData.json;
    this.sarifStringifiedResults = responseData.sarif;

    if (isJson) {
      this.code = firstErr.code;
    }
  }
}

export class FoundIssuesError extends CustomError {
  public jsonStringifiedResults: string;
  public sarifStringifiedResults: string;

  constructor(responseData: ResponseData) {
    super(responseData.response);
    this.code = 'VULNS' as any;
    this.strCode = 'VULNS';
    this.userMessage = responseData.response;
    this.jsonStringifiedResults = responseData.json;
    this.sarifStringifiedResults = responseData.sarif;
  }
}
