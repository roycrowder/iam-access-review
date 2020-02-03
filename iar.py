# -*- coding: utf-8 -*-
"""Identity access report to generate and analyze AWS IAM policies for overprescribed permissions.

This module should be used to generate last access service details for IAM policies and analyze
each service to determine if it is not required in the policy based on a maximum number of days
unused.

Todo:
    * Many policies makes for a long run serially. Integrate threading to speed up the querying.
        * Beware rate limits though!
"""

import logging
from datetime import datetime, timedelta, timezone
from os.path import abspath

import boto3
from botocore.exceptions import WaiterError
from botocore.waiter import WaiterModel, create_waiter_with_client

from waiters import (LAST_ACCESS_DETAILS_WAITER_NAME,
                     last_access_details_waiter_config)

# Initialize logging
logger = logging.getLogger(__name__)

class PolicyScope:
    """Constants mapped to IAM policy scope.
    
    This class is used to define a series of AWS IAM policy scopes which are used
    to query for lists of policies in an AWS account. Each constant is defined as follows:

        - LOCAL: Targets only custom, un-managed IAM policies
        - AWS: Targets AWS managed policies
        - All: Targets all managed and un-managed policies
    """
    LOCAL = 'Local'
    AWS = 'AWS'
    ALL = 'All'


class IdentityAccessReport:
    """This class is used to generate and report on Service Last Access Details.
    
    In addition to reporting, it has the capability to determine whether a particular policy
    is overprescribed.

    Example:
        report = IdentityAccessReport()
        report.run()
        pprint.pprint(report.overprescribed_policies())
    """
    def __init__(self,
                 profile_name='default',
                 waiter_delay=1,
                 max_attempts=30,):
        """Initializes logging, the IAM client and waiter.

        Args:
            profile_name (str): defines the profile boto3 should use to authenticate,
                defaults to 'default'
            waiter_delay (int): defines the amount of seconds to wait before checking
                if the report ran
            max_attempts (int): defines the maximum number of times to check if the
                report finished
        """
        # Initialize private class variables
        self.__waiter_delay = waiter_delay
        self.__max_attempts = max_attempts
        self.__jobs = []
        self.__json = {}
        self.__policy_arns = []

        # Initialize IAM client
        self.__initialize__iam_client(profile_name)

        # Setup waiter for last access job
        self.__waiter_model = WaiterModel(
            last_access_details_waiter_config(waiter_delay, max_attempts))
        self.__last_access_job_waiter = create_waiter_with_client(
            LAST_ACCESS_DETAILS_WAITER_NAME, self.__waiter_model,
            self.__iam_client)

    def __initialize__iam_client(self, profile_name):
        """Initializes the AWS session and IAM client.
        
        Args:
            profile_name (str): the AWS profile used to establish the AWS
                session, defaults to 'default'.
        """
        logger.info('Establishing IAM session with AWS...')
        self.__session = boto3.Session(profile_name=profile_name)
        self.__iam_client = self.__session.client('iam')

    def __query_policies(self, scope, attached):
        """Queries AWS IAM for a list of policies based on user-defined scope and role attachment.

        This method gathers a list of IAM policies associated with the account
        defined in the profile. It is configured to query policies based on
        user-defined scope and role attachment. The policy ARNs are stored in
        and are accessible from the class property ``policy_arns``.

        Args:
            scope (PolicyScope): defines a class constant mapping to AWS string
                literals defining scope (All, AWS, Local).
            attached (bool): defines whether you want to query for policies
                attached to existing roles or not.
        """
        marker = None # Set None for first run
        while True:
            # Gather the list of policies based on user input
            logger.info(
                'Querying for all policies in scope [%s], attached [%s], marker [%s]' %
                (scope, attached, marker))
            if marker:
                response = self.__iam_client.list_policies(Scope=scope,
                                                        OnlyAttached=attached,
                                                        Marker=marker)
            else:
                response = self.__iam_client.list_policies(Scope=scope,
                                                        OnlyAttached=attached)
            logger.debug(response)

            # If response is not paginated, store policy ARNs. Otherwise,
            # loop pages and store ARNs.
            truncated = response.get('IsTruncated')
            if truncated:
                marker = response.get('Marker')
                self.__extract_policies(response.get('Policies'))
            else:
                self.__extract_policies(response.get('Policies'))
                break
            
    def __extract_policies(self, policies):
        """Loops through policies and extracts the AWS IAM policy ARNs.

        Args:
            policies (list): list of IAM policies each defined as a dictionary.
        """
        for policy in policies:
            self.__policy_arns.append(policy['Arn'])
        logger.debug(self.__policy_arns)

    def __gather_reports(self):
        """Gets service last access details reports for each job ID.

        This function takes the list of job IDs generated when the reports are run
        and downloads/stores the reports in a JSON format.

        Raises:
            WaiterError: If report does not complete after X seconds.
        """
        # Loop through job IDs
        logger.info('Downloading last access details for each job:')
        for job in self.__jobs:
            job_id = job[1]
            arn = job[0]

            try:
                # Use custom waiter to periodically query the job ID. If job
                # completed successfully, continue rest of try. Otherwise,
                # drop into exception.
                self.__last_access_job_waiter.wait(JobId=job_id)
                logger.info("\tJob completed for arn [" + arn + "]")

                response = self.__iam_client.get_service_last_accessed_details(
                    JobId=job_id)
                logger.debug(response.get('ServicesLastAccessed'))

                self.__json[arn] = response.get('ServicesLastAccessed')

            except WaiterError:
                logger.error(
                    '\tAccess details report not completed after ' +
                    self.__waiter_delay + ' seconds. JobId: ' + job,
                    exc_info=True)

    def __is_overprescribed(self, days, arn, service):
        """Determines if a service is overprescribed by calculating a time delta.

        Args:
            days (int): defines the maximum number of days a policy service should
                exist unused before being flagged as overprescribed.
            arn (str): the IAM policy ARN.
            service (dict): the policy service definition.

        Returns:
            bool: True if overprescribed, False otherwise.
        """
        last_authenticated = service.get('LastAuthenticated')
        time_delta = datetime.now(timezone.utc) - last_authenticated

        overprescribed = False
        if time_delta.days >= days:
            logger.debug(
                '%s - %s is overprescribed by %s days...' %
                (arn, service.get('ServiceName'),
                 time_delta.days - days))
            overprescribed = True

        return overprescribed

    @property
    def policy_arns(self):  # Readonly
        """list(str): contains AWS IAM policy ARNs"""
        return self.__policy_arns

    @property
    def json(self):  # Readonly
        """dict: contains output of IAM last service access report."""
        return self.__json

    def run(self, scope=PolicyScope.LOCAL, attached=False):
        """Kicks off the creation an AWS IAM report for each IAM policy in an AWS account.

        This method queries IAM policies based on user input, generates a report for each
        policy, gathers the reports and stores the service last accessed data for analysis.

        Args:
            scope (PolicyScope): defines a class constant mapping to AWS string literals 
                defining scope (All, AWS, Local). Defaults to ``PolicyScope.Local``.
            attached (bool): defines whether you want to query for policies attached to
                existing roles or not. Defaults to ``False``.
        """
        self.__query_policies(scope, attached)

        logger.info(
            'Generating last access details for all queried policies:')
        
        # Loop through policies and kick of service last accessed details report.
        for arn in self.__policy_arns:
            response = self.__iam_client.generate_service_last_accessed_details(
                Arn=arn)

            self.__jobs.append((arn, response.get('JobId')))
            logger.info("\t%s --> Job: %s" %
                               (arn, response.get('JobId')))

        self.__gather_reports()

    def overprescribed_policies(self, days=30):
        """Determines if queried policies have service permissions that have not been used for X days.

        This method will yield a ``True`` or ``False`` value for each service defined
        in the IAM policy. This is derived by evaluating the last time the service
        permissions were used against the user-specified maximum number of days
        acceptable. In addition, if a policy service has not been used in the
        allotted AWS IAM reporting window (365 days), this method will outline
        that as well.

        Args:
            days (int): defines the maximum number of days a policy service should
                exist unused before being flagged as overprescribed. Defaults to 30.

        Returns:
            dict: contains each policy ARN as the key and the list of services that are considered overprescribed.

        Raises:
            ValueError: If `days` > 365
        """
        # Reporting window for AWS IAM is a hard 365 days. Make sure we can't
        # exceed that.
        if days > 365:
            logger.error('days set to %s, cannot be greater than 365' %
                                days)
            raise ValueError('days cannot be greater than 365')

        policies = {}

        # Loop through each policy
        for arn, services in self.__json.items():
            overprescribed_services = []
            # Loop through each policy's services to determine if they
            # are overprescribed.
            for service in services:
                last_authenticated = service.get('LastAuthenticated')
                # If last authenticated key exists, process time delta. Otherwise,
                # automatically flag service as overprescribed based on comment
                # below.
                if last_authenticated is not None:
                    # Calculate the delta between the last authenticated field
                    # and the current run time.
                    if self.__is_overprescribed(days, arn, service):
                        overprescribed_services.append(service)
                else:
                    # A service that appears in the report but does not contain the
                    # field 'LastAuthenticated' is defined as an overprescribed service
                    # by the boto3 documentation. See below:
                    #    LastAuthenticated: This field is null if no IAM entities attempted
                    #                       to access the service within the reporting period.
                    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_service_last_accessed_details_with_entities
                    logger.debug(
                        "%s - %s missing LastAuthenticated field, not used within reporting period, flagging overprescribed"
                        % (arn, service.get('ServiceName')))
                    overprescribed_services.append(service)

            policies[arn] = overprescribed_services

        return policies
